#!/usr/bin/python3
# -*- coding: utf-8 -*-

#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""
This program performs a number of check to have an educated guess as to
whether someone can be consider as 'active' or not within the fedora
project.
"""

import argparse
import json
import koji
import logging
import shutil
import sys
import urllib.parse
import urllib.request
import urllib_gssapi
import xmlrpc

from datetime import datetime
from bodhi.client.bindings import BodhiClient
from bugzilla import Bugzilla


# Initial simple logging stuff
logging.basicConfig()
log = logging.getLogger("active-user")

terminal_columns = shutil.get_terminal_size().columns


def print_info_with_time(info, time):
    time = datetime.fromtimestamp(int(time)).strftime('%F')
    print(f"   {time} {info[:terminal_columns - 15]}")


def fetch_json(url):
    log.debug(f"Fetching {url}")

    stream = urllib.request.urlopen(url)
    json_data = json.loads(stream.read())
    stream.close()

    return json_data


def _get_bodhi_history(username):
    """ Print the last action performed on bodhi by the given FAS user.

    :arg username, the fas username whose action is searched.
    """
    bodhiclient = BodhiClient("https://bodhi.fedoraproject.org/")

    print()
    print('Last package updates on bodhi:')
    log.debug(f'Querying Bodhi for user: {username}')
    json_obj = bodhiclient.query(user=username, desc=True)

    if json_obj['updates']:
        for update in json_obj['updates']:
            print('   {0} on package {1}'.format(
                update["date_submitted"], update["title"]))
    else:
        print('   No activity found on bodhi')


def _get_bugzilla_history(email, fas_info, all_comments=False):
    """ Query the bugzilla for all bugs to which the provided email
    is either assigned or cc'ed. Then for each bug found, print the
    latest comment from this user (if any).

    :arg email, the email address used in the bugzilla and for which we
    are searching for activities.
    :arg all_comments, boolean to display all the comments made by this
    person on the bugzilla.
    """
    bzclient = Bugzilla(url='https://bugzilla.redhat.com/xmlrpc.cgi')

    print()
    print("Last Bugzilla activity:")
    log.debug(f'Querying Bugzilla for email: {email}')

    bugbz = bzclient.query({
        'emailtype1': 'substring',
        'emailcc1': True,
        'emailassigned_to1': True,
        'query_format': 'advanced',
        'order': 'last_change_time',
        'bug_status': ['ASSIGNED', 'NEW', 'NEEDINFO'],
        'email1': email
    })
    print(f'   {len(bugbz)} bugs assigned, cc or on which {email} commented')
    # Retrieve the information about this user
    try:
        user = bzclient.getuser(email)

        ids = [bug.bug_id for bug in bugbz]
        for bug in bzclient.getbugs(ids):
            log.debug(f"Checking bug #{bug.id}")
            user_coms = [
                com
                for com in bug.longdescs
                if com['creator_id'] == user.userid
            ]

            if user_coms:
                for comment in user_coms:
                    comment_time = datetime.strptime(comment['time'].value,
                                                     "%Y%m%dT%H:%M:%S"
                                                     ).timestamp()
                    print_info_with_time(f"#{bug.id} "
                                         f"({bug.product}/{bug.component}) "
                                         f"{bug.summary}",
                                         comment_time)
                    if not all_comments:
                        break
            elif bug.assigned_to in [fas_info['human_name'],
                                     fas_info['username']]:
                create_time = datetime.strptime(bug.creation_time.value,
                                                "%Y%m%dT%H:%M:%S"
                                                ).timestamp()
                print_info_with_time(f"#{bug.id} got assigned to {email}",
                                     create_time)

    except xmlrpc.client.Fault as e:
        print(f"There was an error querying for '{email}':")
        print(e)


def _get_koji_history(username):
    """
    Print the last builds made by this user in koji.
    :arg username, the fas username whose history is investigated.
    """
    kojiclient = koji.ClientSession('https://koji.fedoraproject.org/kojihub')

    print('Last action on koji:')
    log.debug(f'Search last history element in koji for {username}')

    user_data = kojiclient.getUser(username)

    if not user_data:
        print(f"User {username} not found.")
        return

    builds = kojiclient.listBuilds(userID=user_data["id"], state=1,
                                   queryOpts={"limit": 10, "order":
                                              "-build_id"})

    if builds:
        for build in builds:
            print_info_with_time(f"built {build["nvr"]}", build["creation_ts"])
    else:
        print("   No activity found on koji")


def _get_last_email_list(email):
    """ Let's find the last email sent by this email.

    :arg email, the email address to search on the mailing lists.
    """
    print()
    print('Last email on mailing list:')
    log.debug(f'Searching activity for {email} on the Fedora mailing lists')
    url = ("https://lists.fedoraproject.org/archives/api/sender/"
           f"{email}/emails/")
    data = fetch_json(url)
    if not data["count"]:
        print("   No activity found on Fedora mailing lists")
    else:
        for entry in data["results"]:
            ml = entry["mailinglist"].replace(
                    'https://lists.fedoraproject.org/archives/api/list/',
                    '')
            print_info_with_time(f"{email} as {entry["sender_name"]} mailed "
                                 f"{ml[:-1]}",
                                 datetime.fromisoformat(
                                     entry["date"]).timestamp())


def _get_fedmsg_history(username):
    """ Using datagrepper, returns the last 10 actions of the user
    according to his/her username over the last year.

    :arg username, the fas username whose action is searched.
    """
    print()
    print('Last actions performed according to fedmsg:')
    log.debug(f'Searching datagrepper for the action of {username}')
    url = 'https://apps.fedoraproject.org/datagrepper/raw'\
        f'?user={username}&order=desc&delta=31104000&meta=subtitle&'\
        'rows_per_page=10'
    jsonobj = fetch_json(url)
    for entry in jsonobj['raw_messages']:
        print_info_with_time(entry['meta']['subtitle'],
                             int(entry['timestamp']))
        if 'meetbot' in entry['topic']:
            done = False
            if username in entry['msg']['chairs']:
                print_info_with_time(f"{username} chaired", entry["timestamp"])
                done = True

            for a in entry['msg']['attendees']:
                if username == a["name"]:
                    print_info_with_time(f"{username} participated",
                                         entry["timestamp"])
                    done = True

            if not done:
                # datagrepper returned this message for our user, but the user
                # doesn't appear in the message.  How?
                raise ValueError("This shouldn't happen.")


def _get_fas_info(username):
    """ Retrieve user information from FAS.

    :arg username, the fas username from who we would like to see information
    """

    log.debug(f'Querying FAS for user: {username}')
    url = (f"https://fasjson.fedoraproject.org/v1/users/{username}/")

    # We need to handle Kerberos in fetching URL
    handler = urllib_gssapi.HTTPSPNEGOAuthHandler()
    opener = urllib.request.build_opener(handler)
    urllib.request.install_opener(opener)

    try:
        data = fetch_json(url)
    except urllib.error.HTTPError as err:
        if err.code == 401:
            print("You need Kerberos ticket. Please run kinit.")
        else:
            print(err)
        sys.exit(-1)

    return data['result']


def main():
    """ The main function."""
    parser = setup_parser()
    args = parser.parse_args()

    global log
    if args.debug:
        log.setLevel(logging.DEBUG)
    elif args.verbose:
        log.setLevel(logging.INFO)

    fas_info = {'human_name': '', 'username':''}

    try:
        if args.username:
            if not args.nofas:
                fas_info = _get_fas_info(args.username)
            if not args.nokoji:
                _get_koji_history(args.username)
            if not args.nobodhi:
                _get_bodhi_history(args.username)
            if not args.nofedmsg:
                _get_fedmsg_history(args.username)

        if args.email:
            email = args.email
        elif 'emails' in fas_info:
            email = fas_info["emails"][0]
        else:
            # no email, our job is done
            sys.exit(0)

        if 'rhbzemail' in fas_info and fas_info['rhbzemail'] is not None:
            bugemail = fas_info["rhbzemail"]
        else:
            bugemail = email

        if not args.nolists:
            _get_last_email_list(email)
        if not args.nobz:
            _get_bugzilla_history(bugemail, fas_info, args.all_comments)

    except Exception as err:
        if args.debug:
            log.exception(err)
        else:
            log.error(err)

        return 1

    return 0


def setup_parser():
    """
    Set the command line arguments.
    """

    parser = argparse.ArgumentParser(
        prog="fedora_active_user")
    # General connection options
    parser.add_argument('--user', dest="username",
                        help="FAS username")
    parser.add_argument('--email', dest="email",
                        help="FAS or Bugzilla email looked for")
    parser.add_argument('--nofas', action='store_true',
                        help="Do not check FAS")
    parser.add_argument('--nokoji', action='store_true',
                        help="Do not check koji")
    parser.add_argument('--nolists', action='store_true',
                        help="Do not check mailing lists")
    parser.add_argument('--nobodhi', action='store_true',
                        help="Do not check bodhi")
    parser.add_argument('--nobz', action='store_true',
                        help="Do not check bugzilla")
    parser.add_argument('--nofedmsg', action='store_true',
                        help="Do not check fedmsg")
    parser.add_argument('--all-comments', action='store_true',
                        help="Prints the date of all the comments made by this"
                             " person on bugzilla")
    parser.add_argument('--verbose', action='store_true',
                        help="Gives more info about what's going on")
    parser.add_argument('--debug', action='store_true',
                        help="Outputs bunches of debugging info")
    return parser


if __name__ == '__main__':
    sys.exit(main())

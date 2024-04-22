#!/bin/env python3

import os
import sys
import logging
from pathlib import Path
import dropbox
from dropbox import DropboxOAuth2FlowNoRedirect
from dropbox.exceptions import ApiError
import json

script_name = os.path.basename(sys.argv[0])

# Script requires three inputs:
def noisy_getenv(name):
    if name not in os.environ:
        print(f"Please export {name}=<value> and restart.",file=sys.stderr)
        exit(1)
    return os.environ[name]


INSTRUCTIONS="""
1. Go to: {url}
2. Click 'Allow' (you might have to log into Dropbox first).
3. Copy the authorization code.
"""

def get_refresh_token( app_key, app_secret, refresh_token=None ):
    """Validate the existing refresh token and return it. If it is not valid, or if none is provided, get a new one and return it. """
    if refresh_token:
        logging.info("refresh_token exists")
        dbx = dropbox.Dropbox(
            app_key=app_key,
            app_secret=app_secret,
            oauth2_refresh_token=refresh_token
        )
        try:
            dbx.users_get_current_account()

            logging.info("Using our existing refresh token")
            return refresh_token
        except dropbox.exceptions.AuthError as e:
            logging.info("Authorization error: %s. Getting a new refresh token",e)

    # No refresh token exists
    logging.info("Initiating New OAuth flow.")
    flow = DropboxOAuth2FlowNoRedirect( app_key, app_secret, token_access_type="offline" )

    authorize_url = flow.start()
    print(INSTRUCTIONS.format(url=authorize_url))

    auth_code = input("Enter the authorization code here: ")

    try:
        oauth_result = flow.finish(auth_code)
        print("To store the refresh token, put this in your .zshrc file:")
        print(f"export DROPBOX_REFRESH_TOKEN={oauth_result.refresh_token}")
        logging.info("Stored new refresh token")
        return oauth_result.refresh_token
    except dropbox.exceptions.AuthError as e:
        logging.critical(e)
        sys.exit("Authorization error!")

def main():
    APP_KEY       = noisy_getenv("DROPBOX_APP_KEY")
    APP_SECRET    = noisy_getenv("DROPBOX_APP_SECRET")

    # If we have a refresh token, validate it.

    REFRESH_TOKEN = os.environ.get("DROPBOX_REFRESH_TOKEN",None)
    refresh_token = get_refresh_token(APP_KEY, APP_SECRET, REFRESH_TOKEN)
    with dropbox.Dropbox(
            app_key=APP_KEY,
            app_secret=APP_SECRET,
            oauth2_refresh_token=refresh_token ) as dbx:
        try:
            account = dbx.users_get_current_account()
            print(f"Dropbox display name: {account.name.display_name}")
        except ApiError as e:
            logging.critical(e)
            sys.exit("Dropbox API error!")

        print("Documentation here: https://dropbox-sdk-python.readthedocs.io/en/latest/")
        for attr in dir(account):
            if attr[0]!='_':
                print(f"account.{attr} = ",getattr(account,attr))

        print("list files:")
        for entry in dbx.files_list_folder("").entries:
            print(entry.name)


if __name__ == '__main__':
    main()

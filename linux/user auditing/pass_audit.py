#!/usr/bin/env python
# Script for auditing users and curating a user whitelist
# Ryan Stonebraker
# 02/23/2020

import os
import subprocess
import json
from getpass import getpass
from datetime import datetime


class UserAudit():
    def __init__(self, whitelist, log):
        self.logfile = log
        self.sudoers = {}
        self.users = {}
        self.whitelisted = {}
        self.whitelist_file = whitelist
        self.user_headers = ["username", "password", "uid", "gid", "comment", "home", "shell"]

        with open(self.whitelist_file, "r") as whitelist_reader:
            cached_whitelist = [json.loads(user) for user in whitelist_reader.read().split("\n") if user]
            self.cached_whitelist = {user["username"]: user for user in cached_whitelist}


    def check_cached_whitelist(self, user):
        if user == self.cached_whitelist[user["username"]]:
            self.whitelisted[user["username"]] = user
            del self.cached_whitelist[user["username"]]
        else:
            print(user["username"], "has changed since last audit!\n\tPrevious:", self.cached_whitelist[user["username"]], "\n\tNew:", user)
            accept_new = input("Accept changes? (y/n): ")
            if accept_new != "y":
                self.audit_user(user["username"], user, current_user=user, cached_user=self.cached_whitelist[user["username"]])
            else:
                self.whitelisted[user["username"]] = user


    def get_current_users(self):
        self.sudoers = {}
        self.users = {}
        current_users = os.popen("cat /etc/passwd").read()
        for user in [fields.split(":") for fields in current_users.split("\n") if len(fields.split(":")) == 7]:
            user = {self.user_headers[i]: user[i] for i in range(len(self.user_headers))}
            user["groups"] = sorted(list(set([group.strip() for group in os.popen("groups %s" % user["username"]).read().split(" ") if group and group != ":"])))
            
            if user["username"] in self.cached_whitelist:
                self.check_cached_whitelist(user)        
            elif "sudo" in user["groups"] or "wheel" in user["groups"]:
                self.sudoers[user["username"]] = user
            else:
                self.users[user["username"]] = user


    def audit_options(self, username, sudoer_group=None, current_user=None, cached_user=None):
        options = [
            ("Don't add to whitelist. (added by default)", "Not added to whitelist.",  "dont_whitelist"),
            ("Change password.", "New Password: ", "sudo passwd " + username),
            ("Delete user.", "User deleted.", "sudo deluser " + username)
        ]
        if sudoer_group:
            options.append(("Remove from sudoers", "User removed from sudoers.", "sudo gpasswd -d " + username + " " + sudoer_group))
        if cached_user:
            revert_cached = ""
            for group in [group for group in current_user["groups"] if group not in cached_user["groups"]]:
                revert_cached += "sudo gpasswd -d %s %s; " % (username, group)
            add_groups = ",".join([group for group in cached_user["groups"] if group not in current_user["groups"]])
            if add_groups:
                revert_cached += "sudo usermod -aG %s %s; " % (add_groups, username)
            if current_user["shell"] != cached_user["shell"]:
                revert_cached += "usermod --shell %s %s; " % (cached_user["shell"], username)
            options.append(("Revert to cached user", "User reverted (password unchanged).", revert_cached))
        [print("%i: %s" % (i, option[0])) for i, option in enumerate(options)]
        return options


    def audit_user(self, username, user, user_type="user", current_user=None, cached_user=None):
        print(user)
        actions_performed = []
        options = self.audit_options(username, "sudo" if "sudo" in user["groups"] else "wheel", current_user, cached_user)
        selected_options = input(username + " is a non-cached " + user_type + ". What do you want to do? (type numbers): ")
        selected_options = [int(option) for option in selected_options if option]
        whitelist = True
        for option in selected_options:
            action = options[option][2]
            prompt = getpass(options[option][1]) if "passwd" in action else print(options[option][1])
            actions_performed.append(action)
            if action == "dont_whitelist":
                whitelist = False
            elif "passwd" in action:
                    os.popen("echo '%s:%s' | sudo chpasswd" % (username, prompt))
            elif action:
                actions_performed.append(os.popen(action).read())
        if whitelist:
            self.whitelisted[user["username"]] = user
        print()
        return actions_performed
        

    def write_whitelist(self):
        with open("~" + self.whitelist_file, "w") as whitelist_writer:
            with open(self.whitelist_file, "r") as whitelist_reader:
                whitelist_writer.write(whitelist_reader.read())

        with open(self.whitelist_file, "w") as whitelist_writer:
            for _, user in self.whitelisted.items():
                whitelist_writer.write(json.dumps(user) + "\n")


    def create_log(self, actions_log):
        with open(self.logfile, "w") as log_writer:
            log_writer.write("# User audit file written on " + datetime.isoformat(datetime.now()) + "\n")

            self.get_current_users()
            log_writer.write("\nsudoers:\n")
            for sudoer in self.sudoers:
                log_writer.write("\t%s\n" % sudoer)
            
            log_writer.write("\n\n")
            for user, user_actions in actions_log.items():
                log_writer.write("%s:" % user)
                for action in user_actions:
                    log_writer.write("\n\t%s" % action)
                log_writer.write("\n")


    def audit(self):
        self.get_current_users()
        actions_log = {}
        for username, sudoer in self.sudoers.items():
            actions_log[username] = self.audit_user(username, sudoer, "sudoer")
        for username, user in self.users.items():
            actions_log[username] = self.audit_user(username, user)

        print("Creating new whitelist...")
        self.write_whitelist()

        print("Writing to log...")
        self.create_log(actions_log)

if __name__ == "__main__":
    timestamp = datetime.isoformat(datetime.now())
    audit = UserAudit(whitelist="whitelist.txt", log="logs/user-audit-%s.log" % timestamp)
    audit.audit()
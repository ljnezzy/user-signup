#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import re


form = """
<!DOCTYPE html>
<html>
    <head>
        <title>Signup</title>
            <style type="text/css">
               span.error {
                    color:red;
                }
            </style>
    </head>
    <body>
        <h1>Signup</h1>
    </body>
    </html>
        <form method="post">
            <table>
                <tbody>
                    <tr>
                        <td>
                            <label for="username">Username</label>
                        </td>
                        <td>
                            <input name="username" type="text" value ="%(username_input)s"required><span class="error">%(username_error)s</span>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <label for="password">Password</label>
                        </td>
                        <td>
                            <input name="password" type="password" value required><span class="error">%(password_error)s</span>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <label for="verify">Verify Password</label>
                        </td>
                        <td>
                            <input name="verify" type="password" value required><span class="error">%(verify_error)s</span>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <label for="email">Email (optional)</label>
                        </td>
                        <td>
                            <input name="email" type="email" value= %(email_input)s><span class="error">%(email_error)s</span>
                        </td>
                    </tr>
                </tbody>
            </table>
            <input type="submit">
        </form>
                    """

USER_RE  = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE  = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class MainHandler(webapp2.RequestHandler):
    def write_form(self, username_error="",password_error="",verify_error="",email_error="",username_input="",email_input=""):
        self.response.out.write(form % {"username_error" : username_error,
                                        "password_error" : password_error,
                                        "verify_error"   : verify_error,
                                        "email_error"    : email_error,
                                        "username_input" : username_input,
                                        "email_input"    : email_input})
    def get(self):
        self.write_form()

    def post(self):
        username            = self.request.get("username")
        password            = self.request.get("password")
        verify              = self.request.get("verify")
        email               = self.request.get("email")
        have_username_error = False
        have_password_error = False
        have_verify_error   = False
        have_email_error    = False
        error               = False
        user_error_text     = ""
        pass_error_text     = ""
        verify_error_text   = ""
        email_error_text    = ""

        if not valid_username(username):
            have_username_error = True
            error               = True
            user_error_text="Please enter a valid username"

        if not valid_password(password):
            is_error = True
            error    = True
            pass_error_text="Please enter a valid password"

        elif password != verify:
            is_error = True
            error    = True
            verify_error_text="Passwords do not match"

        if not valid_email(email):
            is_error = True
            error    = True
            email_error_text="Please enter a valid email address"

        if error == True:
            self.write_form(username_error=user_error_text,password_error=pass_error_text,verify_error=verify_error_text,email_error=email_error_text,username_input=username,email_input=email)
        else:
            self.redirect('/welcome?username=' + username)

class WelcomePage(webapp2.RequestHandler):
    def get(self):
        username = self.request.get("username")
        welcome='''

        <body>
            <h1>Welcome,
        ''' + username + '</h1>'

        """
        </body>
        </html>
        """
        content = welcome
        self.response.write(content)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', WelcomePage),
], debug=True)

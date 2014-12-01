#!/usr/bin/env python
#
# Author: Rajsimman Ravichandiran (Raj)
# 
# Date: Nov 28, 2014

from __future__ import unicode_literals
import tornado.httpserver
import tornado.websocket
import tornado.ioloop
import tornado.options
import tornado.web
from twython import Twython
from tornado.options import define, options
import secrets
from random import randint
import subprocess
import pexpect
import os
import tornado.auth
import oauth2 as oauth
import json
from collections import defaultdict
import urlparse

define("port", default=8888, help="run on the given port", type=int)

tokenDict = {} # in-memory dictionary to store all the user's information (oauth_token, oauth_token_secret, screen_name, oauth_access_token etc.)
counter = 1 # our so-called "key" for our in-memory tokenDict

consumer_key = secrets.CONSUMER_KEY # This is the Kaleidoscope app's consumer key (found on www.twitter.com/apps) 
consumer_secret = secrets.CONSUMER_SECRET # This is the consumer secret (found on www.twitter.com/apps)
access_token = secrets.ACCESS_TOKEN # access token of the app (found on twitter.com/apps)
access_token_secret = secrets.ACCESS_TOKEN_SECRET # access token secret 

pub_remote_ip = [] # list of publisher's IP addrs (They are not stored in a db, hence it will be flushed once the apps stops)
sub_remote_ip = [] # list of subscriber's IP addrs  " "

subLinks = [] # List of links (both enter and leave links) for subscribers to click
 

# This renders the main login page of the app
class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html") 
"""
This class performs the authentication and authorization of the user. Some cleanup can be performed on this class.
1. For example. the auth request tokens may be requested earlier and the if/else block can be removed if and only if the request tokens are the same for all users. If not, then the if/else block should stay (I believe).

2. Also, the tokenDict (our so-called in-memory database can be cleaned too). 
For example, the variables can be stored in a much cleaner fashion (such that join functions can be eliminated) 

"""
class TwitterHandler(tornado.web.RequestHandler):
    def get(self):
        if self.get_argument("oauth_token", None): # This checks whether the app has an oauth_request token. If yes, then exchange the request token for an access token for the user (You need an access token to communicate with twitter on behalf of the user)
            for val in tokenDict: 
                if tokenDict[val]['oauth_token'] == self.get_argument("oauth_token", None): # checks if oauth_request token is recorded in our Dictionary before
                    oauth_token = tokenDict[val]['oauth_token'] # oauth_request_token 
                    oauth_token_secret = tokenDict[val]['oauth_token_secret'] # oauth_request_token secret 
                    token = oauth.Token(oauth_token, oauth_token_secret) # create a request token 
                    token.set_verifier(self.get_argument("oauth_verifier", None)) # set the verifier using the oauth_verifier you received
                    
                    tokenDict[val]['oauth_verifier'] = self.get_argument("oauth_verifier", None) # store the oauth_verifier in the in-memory Dictionary
                    consumer = tokenDict[val]['consumer'] 
                    client = oauth.Client(consumer,token)
                    resp, content = client.request("https://twitter.com/oauth/access_token", "POST") # request to exchange the request oauth tokens for access tokens
                    access_token = dict(urlparse.parse_qs(content))
                    tokenDict[val]['oauth_token_final'] = ", ".join(access_token['oauth_token']) # our oauth_access_token 
                    tokenDict[val]['oauth_token_secret_final'] = ", ".join(access_token['oauth_token_secret']) # oauth_access_token secret
                    print tokenDict
                    if "screen_name" in access_token:
                        screen_name = ", ".join(access_token.get('screen_name')) 
                        tokenDict[val]['screen_name'] = screen_name #store screen_name in the dictionary
			self.render("static/homePage.html") # render the homepage
                        return 
                    else:
                        print "screen_name not found!"

                else:
                        print "Did not find oauth token"  
        else: # This block will be executed when the app does not have an oauth_request_token. So, first, the app has to get the request oauth token to exchange for an access token for the user 
             global counter
             tokenDict[str(counter)] = tokenDict.get(str(counter), {})

             consumer = oauth.Consumer(consumer_key, consumer_secret) # app's consumer key and secret
             tokenDict[str(counter)]['consumer'] = consumer # store the consumer obj. in dict (can be removed later, serves no purpose)
             client = oauth.Client(consumer) 

             resp, content = client.request("https://api.twitter.com/oauth/request_token", "GET") # request a oauth_request_token 
             request_token = dict(urlparse.parse_qsl(content)) 
             oauth_token = request_token['oauth_token']
             oauth_token_secret = request_token['oauth_token_secret']
             tokenDict[str(counter)]['oauth_token'] = oauth_token # store the request token
             tokenDict[str(counter)]['oauth_token_secret'] = oauth_token_secret # store the request token secret
             counter = counter + 1
             self.finish(json.dumps(oauth_token)) # send it back to the GET call in javascript (index.html)

"""
This is the class that sends the screen_name or user name of the user to the homepage when the page is rendered (static/homepage.html)

This uses websockets to communicate between the javascript (located in static/homepage.html) and the web server  
"""
class NameHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print "new connection"

    def on_message(self,data):
        print "data received from server is: %s"% data

        data = dict(urlparse.parse_qsl(data))
        oauth_token = data['oauth_token'] # get the oauth_request_token located in the url 
        for val in tokenDict: 
            if tokenDict[val]['oauth_token'] == oauth_token: # check if oauth_token request is stored in the dict. If yes, the name of the user must be in the dict.
                screen_name = tokenDict[val]['screen_name']
                break        
        
        if not screen_name:
            self.write_message("not found") 
        else: 
            self.write_message(screen_name) # return the screen name back to the javascript 

    def on_close(self):
        self.close()
        print 'connection closed' 

"""
This is the class that sends the subscriber links (both enter and leave links) to the javascript (called from homepage.html) such that the js can post these links on the Subscriber tab of the homepage.html

This also uses websockets
"""
class SubLinksHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print "new connection"

    def on_message(self,data):
        print "data received"
        
        if not subLinks:
          print "no links"
          self.write_message("None")
        else:
          print subLinks
          self.write_message(str(subLinks))

    def on_close(self):
        self.close()
        print 'connection closed'


"""
This is the class that posts tweets on the publisher's twitter home timeline

"""
class PostTweetHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print 'new connection'
        #self.write_message("opened connection")
      
    def on_message(self, data):
        print "data received from server is: %s"% data # The tweet and the oauth_tokens are received from the url 

        data = dict(urlparse.parse_qsl(data)) #parse the url for info
        print data
        tweet = data['tweet']
        oauth_token = data['oauth_token']

        for val in tokenDict:
            if tokenDict[val]['oauth_token'] == oauth_token:
                 rand_int = randint(0,100)
                
                 twitter = Twython(app_key=consumer_key, app_secret=consumer_secret,oauth_token=tokenDict[val]['oauth_token_final'],oauth_token_secret=tokenDict[val]['oauth_token_secret_final'])
                 
                 twitter.update_status(status=tweet) # post tweet 
                 print "tweeted successfully!"
                 break
                  
        self.write_message("http://10.23.0.18:8888/pubs?mult_no=%s"% rand_int) # return the publisher link to javascript call, such that the link can be posted on the publisher's tab on the homepage.html once the tweet was posted 
 
    def on_close(self):
        self.close()
        print 'connection closed'

"""

********************************************           
This is the main backend core of the web server 

The is the class responsible for the processing of getting Publisher's and Subscriber's IP addresses and post Subscriber link of the app's twitter home timeline. 
Since all the subscribers are following the app on twitter, the Subs should be able to view the tweet of the links. Or, alternatively, log into the web application and go to the subscriber tab for the links.
********************************************

"""
class PubSubHandler(tornado.web.RequestHandler):
    def get(self):
        global pub_remote_ip
        global sub_remote_ip
        
        req_uri = self.request.uri # get the url
        url =  dict(urlparse.parse_qsl(req_uri)) # parse the url 

        if('pubs' in req_uri): # if the url is a pub link

            multicast_no = url['/pubs?mult_no'] # the info can be sent better (can be cleaned on the js end)
            oauth_token =  url['oauth_token'] 

            pub_remote_ip.append(str(self.request.remote_ip)) # store it in the list 
            status = 'Subscribers enter link: http://10.23.0.18:8888/subs?mult_no=%s&way=enter and leave link: http://10.23.0.18:8888/subs?mult_no=%s&way=leave'%(multicast_no, multicast_no)
            subLinks.append(status) # store the sub links in the list
            twitter = Twython(app_key=consumer_key, app_secret=consumer_secret,oauth_token=access_token,oauth_token_secret=access_token_secret)
            twitter.update_status(status=status) # post tweet on the timeline
            self.render("static/gotPub.html")    # provide instructions to setup the publisher's VLC player        

        elif('subs' in req_uri): # if the link is a sub link (whether enter or leave link)
            way = url['way']
            
            if( way == 'enter'):
            	sub_remote_ip.append(str(self.request.remote_ip)) 
            elif (way == 'leave'):	
                if str(self.request.remote_ip) in sub_remote_ip:
                    sub_remote_ip.remove((str(self.request.remote_ip)))
                else: 
                    print "Cannot find the IP address from the list to remove!"
            
            self.render("static/gotSub.html")
        else:
            print "just a web server"

        pub_remote_ip = list(set(pub_remote_ip)) # set up the ip addrs to send it to the Sai's algorithm (located in the controller)
        sub_remote_ip = list(set(sub_remote_ip)) # " "

        if pub_remote_ip and sub_remote_ip:
            print "got Both pub and sub"
            print "Pub_remote_ip List:"
            print pub_remote_ip
            print "Sub_remote_ip List: "
            print sub_remote_ip
            try:
                child = pexpect.spawn("ssh stack@10.10.200.10 python /home/stack/kaleidoscope_multicast_alg/start.py "+str(pub_remote_ip)+" "+str(sub_remote_ip))
                child.expect("stack@10.10.200.10's password:")
                child.sendline(secrets.CONTROLLER_PASSWORD)
                child.interact()
            except OSError:
                pass

        else:
            print "didn't get both"


# This class renders the login page (when the user logs out) 
class IndexPageHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html")

def main():
    tornado.options.parse_command_line()
    settings = {
        "static_path": os.path.join(os.path.dirname(__file__), "static"),
        "login_url": "/auth/login",
        "xsrf_cookies": False,
    }

    application = tornado.web.Application([
        (r"/", MainHandler),
        (r"/index.html", IndexPageHandler),
        (r"/authenticate", TwitterHandler),
        (r"/name", NameHandler),
        (r"/ws",PostTweetHandler),
        (r"/pubs", PubSubHandler),
        (r"/subs", PubSubHandler),
        (r"/subLinks", SubLinksHandler),
        
    ], **settings)

    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(options.port, "10.23.0.18")
    #http_server.listen(options.port)

    tornado.ioloop.IOLoop.instance().start()
    
if __name__ == "__main__":

    main()


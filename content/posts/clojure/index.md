---
layout: post
title: Clojure SSTI
categories:
- Web App Security
tags:
- Clojure
- render-file
- SSTI
date: 2024-12-28
summary: In the 0xL4ugh CTF 2024, there was a web challenge with a peculiar programming language used for web development called Clojure. My team solved the challenge but information on the web is almost nonexistent. In today's blog post, I will explain my thought process and depict how we solved the challenge. 
description: In the 0xL4ugh CTF 2024, there was a web challenge with a peculiar programming language used for web development called Clojure. My team solved the challenge but information on the web is almost nonexistent. In today's blog post, I will explain my thought process and depict how we solved the challenge. 
cover:
  image: images/post_img.png
---

My team occasionally participates in ctfs at weekends and we get together to participate in 0xLa4gh CTF hosted by CTF.ae. The CTF had nice challenges because they were different from the traditional CTF challenges. One of them was a web challenge called "Manifesto". 

The challenge description was the following: *This is an easy challenge, except... it's written in Clojure. Can you find your way through all of these parentheses and come out victorious? - @aelmo*

We are given a Dockerfile and the app files. Looking at the Dockerfile we have identified that the flag is in the env vars and it's not used in the app code so our goal is to read the environment variables.

The code has the following structure:
- Dockerfile
- project.clj
- resources
  - public/static/style.css
  - templates
    - gists.html
    - index.html
    - layout.html
    - login.html
- src
  - manifesto
    - core.clj

Our main focus would be the core.clj which contains the web app code.

## Analyzing the code

The first thing I did was to understand what is clojure. Clojure is a similar language as Lisp which is based on Java. It allows for a robust, practical, and fast programming language. 

Note: The Java will be nice later ;)


core.clj:
```clj
(ns manifesto.core
  (:require [clojure.java.io :as io]
            [clojure.core :refer [str read-string]]
            [ring.adapter.jetty :refer [run-jetty]]
            [ring.util.response :as r]
            [ring.middleware.resource :refer [wrap-resource]]
            [ring.middleware.params :refer [wrap-params]]
            [ring.middleware.session :refer [wrap-session]]
            [selmer.parser :refer [render-file]]
            [cheshire.core :as json]
            [environ.core :refer [env]]))

;; thread-safe stores powered by clojure atoms
(defonce server (atom nil))
(def users (atom {}))

;; configure selmer path
(selmer.parser/set-resource-path! (io/resource "templates"))

;; records
(defrecord User [username password gists])

;; services
(defn insert-user
  ;; clojure's multiple-arity functions are elegant and allow code reuse
  ([username password] (insert-user username password []))
  ([username password gists] (swap! users assoc username (->User username password gists))))
(defn insert-gist [username gist] (if (contains? @users username)
                                    (swap! users assoc-in [username :gists]
                                           (conj (get-in @users [username :gists]) gist)) nil))

;; utilities
(defn json-response [m] {:headers {"Content-Type" "application/json"}
                         :body (json/generate-string m)})

(:password (@users "admin"))
[(defn routes [{:keys [request-method uri session query-params form-params]}]
   (cond
     ;; index route
     (re-matches #"/" uri)
     (-> (r/response
          (render-file "index.html"
                       {:prefer (or (query-params "prefer") (session "prefer") "light")
                        :username (session "username")
                        :url uri}))
         (assoc :session (merge {"prefer" "light"} session query-params)))

     ;; display user gists, protected for now
     (re-matches #"/gists" uri)
     (cond (not= (session "username") "admin")
           (json-response {:error "You do not have enough privileges"})

           (= request-method :get)
           (r/response
            (render-file "gists.html"
                         {:prefer (session "prefer")
                          :username (session "username")
                          :gists (get-in @users [(session "username") :gists])
                          :url uri}))

           (= request-method :post)
           (let [{:strs [gist]} form-params]
             ;; clojure has excellent error handling capabilities
             (try
               (insert-gist (session "username") (read-string gist))
               (r/redirect "/gists")
               (catch Exception _ (json-response {:error "Something went wrong..."}))))

           :else
           (json-response {:error "Something went wrong..."}))

     ;; login route
     (re-matches #"/login" uri)
     (cond
       (session "username")
       (r/redirect "/")

       (= request-method :get)
       (r/response
        (render-file "login.html"
                     {:prefer (session "prefer")
                      :user (@users (session "username"))
                      :url uri}))
       (= request-method :post)
       (let [{:strs [username password]} form-params]
         (cond
           (empty? (remove empty? [username password]))
           (json-response
            {:error "Missing fields"
             :fields (filter #(empty? (form-params %)) ["username" "password"])})
           :else
           ;; get user by username
           (let [user (@users username)]
             ;; check password
             (if (and user (= password (:password user)))
               ;; login
               (-> (r/redirect "/gists")
                   (assoc :session
                          (merge session {"username" username})))
               ;; invalid username or password
               (json-response {:error "Invalid username or password"})))))
       :else (json-response {:error "Unknown method"}))

     ;; logout route
     (re-matches #"/logout" uri)
     (-> (r/redirect "/") (assoc :session {}))

     ;; detect trailing slash java interop go brr
     (.endsWith uri "/")
     ;; remove trailing slash thread-last macro go brr
     (r/redirect (->> uri reverse rest reverse (apply str)))

     ;; catch all
     :else
     (-> (r/response "404 Not Found")
         (r/status 404))))

 ;; define app and apply middleware
 (def app (-> routes
              (wrap-resource "public")
              (wrap-params)
              (wrap-session {:cookie-name "session" :same-site :strict})))]

;; server utilities
(defn start-server []
  (reset! server (run-jetty (fn [req] (app req))
                            {:host (or (env :clojure-host) "0.0.0.0")
                             :port (Integer/parseInt (or (env :clojure-port) "8080"))
                             :join? false})))

(defn stop-server []
  (when-some [s @server]
    (.stop s)
    (reset! server nil)))

;; convenience repl shortcuts
(comment
  (start-server)
  (stop-server))

;; initialize

(defn -main []
  ((do (insert-user "admin" (str (random-uuid)))
       (insert-gist "admin" "self-reminder #1: with clojure, you get to closure")
       (insert-gist "admin" "self-reminder #2: clojure gives me composure")
       (insert-gist "admin" "self-reminder #3: i 💖 clojure")
       start-server)))
```

Notes from the code:
- There is a function at the bottom called main that initializes the server. The function creates a user with a random UUID as the password and it adds some gists.
- It has four endpoints, /gists, /login, /logout and /.
- /gists needs a session as admin username and renders what string we input with render-file and insert-gist. Rendering already sounds alarms to SSTI.
- /login is a simple endpoint that verifies if the username and password are valid. Since the password is UUID it's impossible to get the password for the admin.
- / is the root endpoint and at first look it only renders the index.html and sets a session for the person which includes the preferred website theme.

## Bypassing the Login form validation using assoc and merge

As I have mentioned in the notes from the code the root endpoint, /, only renders index.html and sets the session cookie with the preferred theme but it is wrong it has a vulnerability because it takes the query parameters and uses them in the session cookie, example `example.com/?param1=value1` in this cases its `param1=value1`. The vulnerable code is `(assoc :session (merge {"prefer" "light"} session query-params)))`. It basically merges the preferred key, the session, and the query parameters in the session cookie.

Since we need a session as admin to use the /gists we use the following payload: `/?username=admin`.

## SSTI in gists using render-file

Accessing the gists endpoint we are presented with a page where we can put stuff and it will be shown.
As said before it uses render-file and the following code to render the page with the input provided by the user:


```html
{% extends "layout.html" %} {% block main %}
<p class="delims">clojure memes</p>
<img src="https://imgs.xkcd.com/comics/lisp_cycles.png" alt="" />
<p class="delims">gists</p>
<div class="gists">
  {% for gist in gists %}
  <p>{{gist}}</p>

  {% endfor %}
</div>
<hr style="margin: 1.5rem 0" />
<form method="POST" action="/gists">
  <label for="gist">Gist:</label>
  <textarea name="gist"></textarea>
  <input type="submit" value="Submit gist" />
</form>
<p class="delims">end of section</p>
{% endblock %}
```

Searching for SSTI for Clojure render-file function on the web is almost nonexistent.
After trying payloads from other engines with no success a CTF colleague remembered me that Clojure is based on Java and doing a more focused search he found the following link: https://ericnormand.me/article/clojure-web-security 

In the link, they talked about how the payloads: `#java.io.FileWriter["myfile.txt"]` and `#=(println "Hello, vulnerability!")` worked with the function read-string from Clojure but it's using render-file. Trying the payloads, they actually work too!!!!

After some time my friend found a payload that uses System from Java to shut down the web app: `#=(eval (System/exit 1))`
Doing one plus one, I took his payload and tried to read the envs with getenv and we got the flag!!!!
Final payload: `#=(eval (System/getenv))`

That was the challenge! 
Thanks for reading to the end!
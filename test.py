from flask import Flask, make_response
from flask_restx import Api, Resource
import logging
from sys import stdout
from pymongo import MongoClient
from netaddr import valid_ipv4, valid_ipv6, IPAddress
import json
import re
import os


flask_app = Flask(__name__)
app = Api(app = flask_app)


#mongo_uri = os.getenv("MONGO_URI", "mongodb://exabgp:1234@localhost:27017/?authSource=exabgp")
mongo_uri = os.getenv("MONGO_URI", "mongodb://exabgpuser:vtHeokPW05-yLfOLSccP@10.150.227.40:27017,10.150.227.41:27017,10.150.227.42:27017/?authSource=admin")
max_blackholes = int(os.getenv("MAX_BLACKHOLES", 80000))
max_flowspecs = int(os.getenv("MAX_FLOWSPECS", 600))
ipv6_nexthop = os.getenv("IPV6_NEXTHOP", "100::192:0:2:1")

name_space = app.namespace('Exabgp', description='Exabgp API')

log_file = os.getenv("LOG_FILE", "/var/log/exabgpapi.log")

if not os.path.exists(log_file):
    try:
        open(log_file, 'w').close()
    except OSError as e:
        if not os.path.isdir(log_file):
            raise

logging.basicConfig(filename=log_file, filemode='a', level=logging.INFO, format='%(asctime)s.%(msecs)03d - %(funcName)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger('Exabgp API').setLevel(logging.INFO)

def logerr(messaggio):
    logging.error(messaggio)
    return messaggio
def loginfo(messaggio):
    logging.info(messaggio)
    return messaggio
    
def fillrulesfromMongo():
    try:
        mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        db = mongo_client["exabgp"]
        flowspecs_collection = db["flowspecs"]
        blackholes_collection = db["blackholes"]
        for entry in flowspecs_collection.find():
            stdout.write(entry["command"]+"\n")
        for entry in blackholes_collection.find():
            stdout.write(entry["command"]+"\n")
        stdout.flush()
    except Exception as e:
        logging.error("Problema durante l'importazione dei dati da Mongo: " + str(e))
fillrulesfromMongo()
        
def getFlowspecCommand(action, srcip, dstip, srcport, dstport):
    if valid_ipv4(srcip) and valid_ipv4(dstip):
        ip_type = "ipv4"
        ip_subnet = "32"
    else:
        logerr("Gli indirizzo devono essere in formato ipv4")
        return None
    if not srcport and not dstport:
        return action+" flow route { match { source-"+ip_type+" "+srcip+"/"+ip_subnet+";destination-"+ip_type+" "+dstip+"/"+ip_subnet+";} then { discard;}}"
    if dstport and not srcport:
        if dstip == "0.0.0.0":
            return action+" flow route { match { source-"+ip_type+" "+srcip+"/"+ip_subnet+";destination-port "+dstport+";} then { discard;}}"
        else:
            return action+" flow route { match { source-"+ip_type+" "+srcip+"/"+ip_subnet+";destination-"+ip_type+" "+dstip+"/"+ip_subnet+";destination-port "+dstport+";} then { discard;}}"
    return action+" flow route { match { source-"+ip_type+" "+srcip+"/"+ip_subnet+";destination-"+ip_type+" "+dstip+"/"+ip_subnet+";source-port "+srcport+"; destination-port "+dstport+";} then { discard;}}"

def getBlackHoleCommand(action, ip):
    if valid_ipv4(ip):
        ip_subnet = "32"
        ip_next_hop = "self"
    elif valid_ipv6(ip):
        ip_subnet = "128"
        ip_next_hop = ipv6_nexthop
    else:
        logerr("Gli indirizzo devono essere in formato ipv4 o ipv6")
        return None
    return action+" route "+ip+"/"+ip_subnet+" next-hop "+ip_next_hop

def callFlowspec(ispost ,srcip, dstip, srcport, dstport):
        if not valid_ipv4(srcip) or not valid_ipv4(dstip):
            return logerr("Gli indirizzo devono essere in formato ipv4"), 400
        try:
            if srcport and dstport:
                if not 1 <= int(srcport) <= 65535 or not 1 <= int(dstport) <= 65535:
                    return logerr("Le porte devono essere comprese tra 1 65535"), 400  
            if dstport and not srcport:
                if not 1 <= int(dstport) <= 65535:
                    return logerr("Le porte devono essere comprese tra 1 65535"), 400
        except ValueError:
            return logerr("Le porte devono essere interi"), 400
        try:
            mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = mongo_client["exabgp"]
            flowspecs_collection = db["flowspecs"]
            id_comando = srcip + dstip + srcport + dstport
            if ispost:
                comando = getFlowspecCommand("announce", srcip, dstip, srcport, dstport)
                if comando is None:
                    return logerr("Gli indirizzo devono essere in formato ipv4 o ipv6"), 400
                if flowspecs_collection.count_documents({}) >= max_flowspecs:
                    return loginfo("Limite ip in flowspecs raggiunto: " + str(max_flowspecs)), 412
                flowspecs_collection.insert_one({"_id": id_comando, "command": comando})
                stdout.write(comando +"\n")
                stdout.flush()
                return loginfo("Regola inserita in Flowspec"), 200
            else:
                comando = getFlowspecCommand("withdraw", srcip, dstip, srcport, dstport)
                flowspecs_collection.delete_one({"_id": id_comando})
                stdout.write(comando +"\n")
                stdout.flush()
                return loginfo("Regola rimossa da Flowspec"), 200
        except Exception as e:
            return logerr("Problema Mongo: " + str(e)),500


@name_space.route("/blackhole/<string:ip>")
class Blackhole(Resource):
    def post(self, ip):
        logging.info("chiamata post blackhole per ip: %s", ip)
        try:
            ip_parsed = IPAddress(ip)
        except Exception as e:
            return logerr("L'indirizzo deve essere un ipv4/ipv6 valido"), 400
        if ip_parsed.is_multicast() or ip_parsed.is_loopback() or ip_parsed.is_private() or ip_parsed.is_reserved() or ip_parsed.is_link_local():
            return logerr("L'indirizzo deve essere un ipv4/ipv6 pubblico"), 400

        comando = getBlackHoleCommand("announce", ip)
        try:
            mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = mongo_client["exabgp"]
            blackholes_collection = db["blackholes"]
            if blackholes_collection.count_documents({}) >= max_blackholes: 
                return loginfo("Limite ip in blackhole raggiunto: " + str(max_blackholes)), 412
            blackholes_collection.insert_one({"_id": ip, "command": comando})
        except Exception as e:
            return logerr("Problema Mongo: " + str(e)), 500
        stdout.write(comando+"\n")
        stdout.flush()
        return loginfo("Ip "+ip+" inserito in blackhole"), 200

    def delete (self, ip ):
        logging.info("chiamata delete blackhole per ip: %s", ip)
        try:
            ip_parsed = IPAddress(ip)
        except Exception as e:
            return logerr("L'indirizzo deve essere un ipv4/ipv6 valido, senza subnet"), 400
        try:
            mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = mongo_client["exabgp"]
            blackholes_collection = db["blackholes"] 
            blackholes_collection.delete_one({"_id": ip})
        except Exception as e:
            return logerr("Problema Mongo: " + str(e)), 500
        stdout.write(getBlackHoleCommand("withdraw", ip)+"\n")
        stdout.flush()
        return loginfo("Ip "+ip+" rimosso da blackhole"), 200

@name_space.route("/flowspec/<string:dstport>/<string:srcip>", defaults={'srcport': "", 'dstip':"0.0.0.0" })
@name_space.route("/flowspec/<string:dstip>/<string:dstport>/<string:srcip>", defaults={'srcport': ""})
@name_space.route("/flowspec/<string:dstip>/<string:dstport>/<string:srcip>/<string:srcport>")
class Flowspec(Resource):
    def post (self, srcip, dstip, srcport, dstport):
        logging.info("chiamata post flowspec per " + srcip + ":" + srcport + " " + dstip+":"+dstport)
        return callFlowspec(True, srcip, dstip, srcport, dstport)

    def delete (self, srcip, dstip, srcport, dstport):
        logging.info("chiamata delete flowspec per " + srcip + ":" + srcport + " " + dstip+":"+dstport)
        return callFlowspec(False, srcip, dstip, srcport, dstport)



@name_space.route("/blackhole/")
class Blackholes(Resource):
    def get (self):
        logging.info("chiamata get blackhole")
        try:
            mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = mongo_client["exabgp"]
            blackholes_collection = db["blackholes"]
            rows = blackholes_collection.find({}, {"command": 1, "_id": 0})
            bh_regex = "announce route (?P<ip>.*)/(32|128) next-hop .*"
        except Exception as e:
            return logerr("Problema Mongo: " + str(e)), 500   
        entries = []
        for row in rows:
            result = re.match(bh_regex, row.get("command"))
            if result:
                entries.append({"ip": result.group('ip')})
        return json.dumps(entries)   

    def delete (self):
        logging.info("chiamata delete all blackhole")
        try:
            mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = mongo_client["exabgp"]
            blackholes_collection = db["blackholes"]
            rows = blackholes_collection.find({}, {"command": 1, "_id": 0})
            for row in rows:            
                blackholes_collection.delete_one(row)
                stdout.write(row.get("command").replace("announce", "withdraw") +"\n")
                stdout.flush()
            return logging.info("Regole Rimosse"), 200                
        except Exception as e:
            return logerr("Problema Mongo: " + str(e)), 500

def toJson(row): # da migliorare un po' macchinoso
    fs_regex_1 = "announce flow route { match { source-ipv(4|6) (?P<srcip>.*)/(32|128);destination-ipv(4|6) (?P<dstip>.*)/(32|128);source-port (?P<srcport>.*); destination-port (?P<dstport>.*);} then { discard;}"
    fs_regex_2 = "announce flow route { match { source-ipv(4|6) (?P<srcip>.*)/(32|128);destination-port (?P<dstport>.*);} then { discard;}"
    fs_regex_3 = "announce flow route { match { source-ipv(4|6) (?P<srcip>.*)/(32|128);destination-ipv(4|6) (?P<dstip>.*)/(32|128);destination-port (?P<dstport>.*);} then { discard;}"
    entry = {}
    result = re.match(fs_regex_1, row)
    if result:
        entry["kind"] = 1
        entry["srcip"] = result.group('srcip')
        entry["dstport"] = result.group('dstport')
        entry["dstip"] = result.group('dstip') 
        entry["srcport"] = result.group('srcport')
        return entry
    result = re.match(fs_regex_3, row)
    if result:
        entry["kind"] = 3
        entry["srcip"] = result.group('srcip')
        entry["dstport"] = result.group('dstport')
        entry["dstip"] = result.group('dstip') 
        return entry
    result = re.match(fs_regex_2, row)
    if result:
        entry["kind"] = 2
        entry["srcip"] = result.group('srcip')
        entry["dstport"] = result.group('dstport')
    return entry

@name_space.route("/flowspec/")
class Flowspecs(Resource):
    def get (self):
        logging.info("chiamata get flowspec")
        try:
            mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = mongo_client["exabgp"]
            flowspecs_collection = db["flowspecs"] 
            rows = flowspecs_collection.find({}, {"command": 1, "_id": 0})
        except Exception as e:
            return logerr("Problema Mongo: " + str(e)), 500   
        entries = []
        for row in rows: 
            entries.append(toJson(row.get("command")))
        return json.dumps(entries)

    def delete (self):
        logging.info("chiamata delete all flowspec")
        try:
            mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = mongo_client["exabgp"]
            flowspecs_collection = db["flowspecs"]
            rows = flowspecs_collection.find({}, {"command": 1, "_id": 0})
            for row in rows:            
                flowspecs_collection.delete_one(row)
                stdout.write(row.replace("announce", "withdraw") +"\n")
                stdout.flush()  
            return logging.info("Regole Rimosse"), 200                            
        except Exception as e:
            return logerr("Problema Mongo: " + str(e)), 500
def html(content):  # Also allows you to set your own <head></head> etc
    return '<html><head>custom head stuff here</head><body>' + content + '</body></html>'

@name_space.route("/monitor/")
class Blackholes(Resource):
    def get (self):
        logging.info("chiamata get monitor")
        try:
            mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = mongo_client["exabgp"]
            blackholes_collection = db["blackholes"]
            flowspecs_collection = db["flowspecs"]
            bl_rows = blackholes_collection.find({}, {"command": 1, "_id": 0})
            fs_rows = flowspecs_collection.find({}, {"command": 1, "_id": 0})
            bh_regex = "announce route (?P<ip>.*)/(32|128) next-hop .*"
        except Exception as e:
            return logerr("Problema Mongo: " + str(e)), 500   
        entries = []
        entries.append("<div style='font-size:180% ;color: green'>FLOWSPECS RULES</div>")
        entries.append("</tr>")
        for row in fs_rows: 
            tmp_row = toJson(row.get("command"))
            if tmp_row["kind"] == 1:
                entries.append(f"<div><span>source IP:</span> <span style='color: red'>{tmp_row['srcip']}</span> <span>source port:</span> <span style='color: red'>{tmp_row['srcport']}</span> <span>destination IP:</span> <span style='color: red'>{tmp_row['dstip']}</span> <span>destination port:</span> <span style='color: red'>{tmp_row['dstport']}</span></div>")
            if tmp_row["kind"] == 3:
                entries.append(f"<div><span>source IP:</span> <span style='color: red'>{tmp_row['srcip']}</span> <span>destination IP:</span> <span style='color: red'>{tmp_row['dstip']}</span> <span>destination port:</span> <span style='color: red'>{tmp_row['dstport']}</span></div>")
            if tmp_row["kind"] == 2:
                entries.append(f"<div><span>source IP:</span> <span style='color: red'>{tmp_row['srcip']}</span> <span>destination port:</span> <span style='color: red'>{tmp_row['dstport']}</span></div>") 
        entries.append("</tr>")  
        entries.append("<div style='font-size:180%;color: green' >BLACKHOLES RULES</div>")  
        entries.append("</tr>")  
        for row in bl_rows:
            result = re.match(bh_regex, row.get("command"))
            if result:
                entries.append(f"<div><span>IP:</span><span style='color: red'>{result.group('ip')}</span></div>")
        response = make_response(''.join(entries))
        response.mimetype = "text/html"
        return response


if __name__ == '__main__':
    flask_app.run(port=8000, debug=True,host="10.150.217.114")

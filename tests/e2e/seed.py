"""Seed a freshly initialized, disposable 1Panel DB; never point at an existing panel."""
import json, secrets, sqlite3, sys
from pathlib import Path
root=Path(sys.argv[1]); instance=sys.argv[2]; backend=sys.argv[3]
assert (root/'DISPOSABLE_TEST_ONLY').exists() and root.name.startswith('onepanel-skills-e2e-')
base=root/'1panel'; db=sqlite3.connect(base/'db/core.db'); key=secrets.token_hex(32)
for k,v in {'ApiInterfaceStatus':'Enable','ApiKey':key,'IpWhiteList':'0.0.0.0/0','ApiKeyValidityTime':'5'}.items():db.execute('update settings set value=? where key=?',(v,k))
db.commit();db.close();a=sqlite3.connect(base/'db/agent.db')
assert a.execute('select count(*) from websites').fetchone()[0]==0
app=a.execute("select id from apps where key='openresty'").fetchone()
if not app:
 a.execute("insert into apps (id,name,key,type,status,resource) values (900001,'OpenResty','openresty','runtime','Normal','local')"); app=(900001,)
app=app[0];detail=a.execute('select id from app_details where app_id=? limit 1',(app,)).fetchone();detail=detail[0] if detail else 0
now='2026-11-08 00:00:00+00:00'
def insert(table,row):a.execute('insert into '+table+' ('+','.join(row)+') values ('+','.join('?' for _ in row)+')',list(row.values()))
insert('app_installs',{'id':1,'created_at':now,'updated_at':now,'name':'skill-e2e','app_id':app,'app_detail_id':detail,'version':'1.27.1.2-5-1-focal','param':'{}','env':json.dumps({'WEBSITE_DIR':str(base/'www')}),'docker_compose':'','status':'Running','container_name':instance,'service_name':'openresty','http_port':18080,'https_port':18443,'sort_order':1,'favorite':0})
insert('websites',{'id':1,'created_at':now,'updated_at':now,'protocol':'HTTPS','primary_domain':'example.com','type':'proxy','alias':'skill-e2e','status':'Running','http_config':'HTTPSOnly','expire_date':'2099-12-31 00:00:00+00:00','proxy':'http://'+backend+':18080','site_dir':'/','website_group_id':1,'website_ssl_id':0,'app_install_id':0,'runtime_id':0,'parent_website_id':0,'error_log':1,'access_log':1,'default_server':0,'ip_v6':0})
a.commit();a.close();f=root/'client.json';f.write_text(json.dumps({'apiKey':key}));f.chmod(0o600)

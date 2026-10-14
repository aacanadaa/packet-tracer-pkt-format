#!/usr/bin/env python3
"""Model-aware corpus miner: exact model -> port names, plus real IOS config samples."""
import sys, re, json, glob, collections, os
sys.path.insert(0,'/home/saoria/testing/packet-tracer-pkt-format')
import pt9
import xml.etree.ElementTree as ET

CORPUS='/home/saoria/testing/packet-tracer-pkt-format/corpus/files'
files=sorted(glob.glob(os.path.join(CORPUS,'**','*.pkt'),recursive=True))+sorted(glob.glob(os.path.join(CORPUS,'**','*.pka'),recursive=True))
TARGETS={'2911','2901','2811','1841','1941','ISR4331','ISR4321','IR1101','IR8340','CGR1240','819HGW','829',
 '2960-24TT','2950-24','2950T-24','3560-24PS','3650-24PS','IE-2000','IE-3400','IE-9320','5505',
 'WLC-2504','WLC-3504','AccessPoint-PT','AccessPoint-PT-A','AccessPoint-PT-N','Server-PT','PC-PT','Laptop-PT',
 '7960','Cloud-PT','Cell-Tower','Router-PT','TabletPC-PT','SMARTPHONE-PT','Sniffer','Meraki-MX65W'}
ports=collections.defaultdict(collections.Counter)
ioss=collections.defaultdict(list)
ok=fail=0
for f in files:
    try:
        root=ET.fromstring(pt9.decode(f,'pkt',verify_tag=False))
    except Exception:
        fail+=1; continue
    ok+=1
    for net in root.iter('NETWORK'):
        devs={}
        for d in net.iter('DEVICE'):
            sid=d.findtext('ENGINE/SAVE_REF_ID')
            te=d.find('ENGINE/TYPE'); t=(te.text or '') if te is not None else ''; mmod=(te.get('model') if te is not None else '') or ''
            
            mdl=mmod
            if sid: devs[sid]=mdl
            if mdl in TARGETS and len(ioss[mdl])<3:
                lines=[l.text or '' for l in d.findall('ENGINE/RUNNINGCONFIG/LINE')]
                if len(lines)>4: ioss[mdl].append({'file':os.path.basename(f),'lines':lines})
        for L in net.iter('LINK'):
            c=L.find('CABLE')
            if c is None: continue
            fa,pa,fb,pb=c.findtext('FROM'),c.findtext('PORT'),c.findtext('TO'),c.findtext('PORT')
            if fa in devs and pa and devs[fa] in TARGETS: ports[devs[fa]][pa.strip()]+=1
            if fb in devs and pb and devs[fb] in TARGETS: ports[devs[fb]][pb.strip()]+=1
print('decoded',ok,'failed',fail)
rep={}
for mdl in sorted(ports):
    rep[mdl]=dict(ports[mdl])
    print(f'\n== {mdl} ({len(ports[mdl])} names)')
    for p,n in ports[mdl].most_common(40): print(f'     {p:28s} {n}')
json.dump({'ports':rep},open('build/port_names.json','w'),indent=1)
json.dump(ioss,open('build/ios_samples.json','w'),indent=1)
print('\nmodels with port evidence:',len(rep))
print('models with ios samples:',{k:len(v) for k,v in ioss.items()})

"""Regress Android's malformed in-kernel BTF failure before packaging."""
from pathlib import Path
import json,subprocess,sys,struct,ctypes,os
f=Path(__file__).resolve().parent
p=Path(sys.argv[1]) if len(sys.argv)>1 else f.parent.parent/'kernel_workspace/common/out-bootfix3/vmlinux'
a=json.loads(subprocess.check_output(['bpftool','-j','btf','dump','file',str(p)]))['types']
types={t['id']:t for t in a};errors=[];variables=0
for t in a:
 if t['kind']!='DATASEC':continue
 end=0
 for v in t['vars']:
  variables+=1
  if v['offset']<end or v['offset']+v['size']>t['size'] or types[v['type_id']]['kind']!='VAR':errors.append({'section':t['name'],'var':v,'previous_end':end})
  end=v['offset']+v['size']
r={'file':str(p),'type_count':len(a),'datasec_variables':variables,'errors':errors}
(f/'evidence').mkdir(exist_ok=True)
(f/'evidence/btf-validation.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r if errors else {k:v for k,v in r.items() if k!='errors'}))
assert not errors,'BTF DATASEC invalid'

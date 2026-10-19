import hashlib,json,pathlib,sys
import profiles
old_exit=profiles.EvidenceServer.__exit__
def diagnostic_exit(self,kind,value,traceback):
    if kind is not None and self.proc.poll() is not None:
        tail=self.proc.stdout.read(65537)
        profiles.ACTIVE_COMMANDS.append({"role":"exited-server-stdout","exit_code":self.proc.returncode,"stdout":tail[:65536].decode(errors="replace"),"truncated":len(tail)>65536})
    return old_exit(self,kind,value,traceback)
profiles.EvidenceServer.__exit__=diagnostic_exit
out=pathlib.Path(sys.argv[sys.argv.index("--output")+1])
result=profiles.main()
data=json.loads(out.read_text());data["diagnostic_wrapper"]={"sha256":hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),"scope":"Retain bounded post-ready stdout only after server has exited; no protocol/source/oracle change."};out.write_text(json.dumps(data,indent=2)+"\n")
raise SystemExit(result)

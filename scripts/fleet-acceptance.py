#!/usr/bin/env python3
"""Qualify real isolated Linux NDS clients; never resets product quotas or clocks."""
from pathlib import Path
import argparse,gzip,json,os,re,secrets,shutil,signal,socket,subprocess,sys,tempfile,time

ROOT=Path(__file__).resolve().parents[1]
TEST='client::fleet_acceptance::native_fleet_member'

def worker(root,executable,index,count,output):
    root=Path(root);output=Path(output)
    assert Path(os.environ['XDG_DATA_HOME'])==root/'data' and (root/'data/keyrings').is_dir()
    child=None
    def interrupted(_signal,_frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted)
    with (output/f'daemon-{index}.log').open('wb') as log:
        daemon=subprocess.Popen(['gnome-keyring-daemon','--foreground','--components=secrets','--unlock','--control-directory',str(root/'control')],stdin=subprocess.PIPE,stdout=log,stderr=log)
        try:
            daemon.stdin.write(secrets.token_urlsafe(32).encode());daemon.stdin.close()
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                assert daemon.poll() is None,'Owned credential service exited'
                p=subprocess.run(['gdbus','call','--session','--dest','org.freedesktop.DBus','--object-path','/org/freedesktop/DBus','--method','org.freedesktop.DBus.GetConnectionUnixProcessID','org.freedesktop.secrets'],capture_output=True,timeout=2)
                if p.returncode==0:
                    assert int(re.findall(rb'\d+',p.stdout)[-1])==daemon.pid,'Credential service is not owned'
                    break
                time.sleep(.1)
            else:raise RuntimeError('Owned credential service did not initialize')
            for epoch in [0,1]:
                env=os.environ|{'NDS_FLEET_EPOCH':str(epoch)}
                # Compression must not become an artificial slow stdout reader
                # for32 simultaneous clients. Preserve the real output directly;
                # compress only after that process has closed its logger.
                raw=output/f'client-{index}-{epoch}.raw'
                with raw.open('xb') as log:
                    child=subprocess.Popen([executable,'--exact',TEST,'--ignored','--nocapture'],env=env,stdout=log,stderr=subprocess.STDOUT)
                    status=child.wait(timeout=3500)
                raw_bytes=raw.stat().st_size
                with raw.open('rb') as source,gzip.open(output/f'client-{index}-{epoch}.log.gz','wb',compresslevel=1) as destination:
                    shutil.copyfileobj(source,destination,65536)
                (output/f'client-{index}-{epoch}-capture.json').write_text(json.dumps({'raw_bytes':raw_bytes,'compressed_bytes':(output/f'client-{index}-{epoch}.log.gz').stat().st_size})+'\n')
                raw.unlink()
                if status:raise RuntimeError(f'Client {index} epoch {epoch} exited {status}')
                child=None
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait()
            daemon.terminate()
            try:daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait()

if len(sys.argv)>1 and sys.argv[1]=='--worker':
    worker(*sys.argv[2:]);raise SystemExit

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixture',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--clients',type=int,choices=range(2,33),default=32)
args=parser.parse_args()
assert sys.platform=='linux' and args.fixture.is_absolute() and args.output.is_absolute()
assert not args.output.resolve().is_relative_to(ROOT) and not args.output.exists()
receipt=json.loads(args.fixture.read_text());assert receipt['status']=='running' and receipt['owner_email'].endswith('.invalid')
for name in ['control_file','stop_marker']:assert Path(receipt[name]).parent.resolve()==args.fixture.parent.resolve()
args.output.mkdir(mode=0o700,parents=True)
source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip())
if args.clients==32 and dirty:raise SystemExit('Full fleet qualification requires a committed source')
assert shutil.disk_usage(args.output).free>=4*1024**3,'Fleet artifacts require 4 GiB free'
# Build first; the runtime uses only this selected test executable.
env=os.environ|{'CARGO_PROFILE_TEST_OPT_LEVEL':'3'}
with (args.output/'build.log').open('w') as log:
    built=subprocess.run(['cargo','test','--locked','--features','development-http','--lib','--no-run','--message-format=json'],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=log,text=True,check=True,timeout=600)
artifacts=[json.loads(line) for line in built.stdout.splitlines() if line.startswith('{')]
executables=[x['executable'] for x in artifacts if x.get('reason')=='compiler-artifact' and x.get('executable') and x.get('profile',{}).get('test')]
assert len(executables)==1
executable=executables[0]
deadline=time.monotonic()+min(3500,receipt['expires_at_unix']-time.time()-20)
if args.clients==32 and deadline-time.monotonic()<3300:raise SystemExit('Start a fresh 3600-second fixture after precompiling')
processes=[];sockets={};history=[]

def event(phase,**values):
    value={'phase':phase,'at':int(time.time()),**values};history.append(value)
    (args.output/'progress.json').write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(value),flush=True)

def check():
    if time.monotonic()>deadline:raise TimeoutError('Fleet lifetime exhausted')
    for i,p in enumerate(processes):
        if p.poll() is not None and p.returncode!=0:raise RuntimeError(f'Owned client supervisor {i} exited {p.returncode}')
    if any(p.stat().st_size>64*1024**2 for p in args.output.glob('*.log*')):raise RuntimeError('Fleet log budget exceeded')
    # These are test-artifact bounds, not SDK queue sizes or product quotas.
    raw_sizes=[]
    for path in args.output.glob('*.raw'):
        try:raw_sizes.append(path.stat().st_size)
        except FileNotFoundError:pass  # Completed workers remove their raw spool.
    if any(size>128*1024**2 for size in raw_sizes) or sum(raw_sizes)>2*1024**3:
        raise RuntimeError('Fleet raw capture budget exceeded')

def receive(connection,index,timeout=600):
    end=min(deadline,time.monotonic()+timeout)
    data=bytearray()
    while not data.endswith(b'\n'):
        check()
        if time.monotonic()>end:raise TimeoutError(f'Client {index} response deadline')
        try:chunk=connection.recv(1)
        except socket.timeout:continue
        if not chunk:raise RuntimeError(f'Client {index} control channel closed')
        data.extend(chunk)
        if len(data)>65536:raise RuntimeError('Fleet response budget exceeded')
    value=json.loads(data)
    assert 'token' not in value,'Credentials must stay in Rust'
    return value

def read(index,timeout=600):
    return receive(sockets[index],index,timeout)

def send(index,action,**values):
    sockets[index].sendall(json.dumps({'action':action,**values}).encode()+b'\n')

def all_clients(action,**values):
    for i in range(args.clients):send(i,action,**values)
    result=[read(i) for i in range(args.clients)]
    event(action,clients=args.clients)
    return result

def uniform(values):
    assert len({(x['cursor'],x['digest']) for x in values})==1
    assert all(x['pending']==0 and x['conflicts']==0 and x['facts']==1056 for x in values)

def mode(value):
    Path(receipt['control_file']).write_text(json.dumps({'mode':value}))
    end=time.monotonic()+15
    while True:
        check()
        if time.monotonic()>end:raise TimeoutError('Owned fixture transition failed')
        try:state=json.loads(args.fixture.read_text())['status']
        except json.JSONDecodeError:state=None
        if state==('running' if value=='online' else 'offline'):return
        time.sleep(.1)

with tempfile.TemporaryDirectory(prefix='nds-fleet-') as directory:
    base=Path(directory);listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    listener.bind(str(base/'control.sock'));os.chmod(base/'control.sock',0o600);listener.listen(64);listener.settimeout(1)
    def connect(expected,epoch):
        while True:
            check()
            try:connection,_=listener.accept();break
            except socket.timeout:continue
        connection.settimeout(1);sockets[expected]=connection
        hello=read(expected,30);assert hello=={'index':expected,'epoch':epoch}
        send(expected,'initialize');return read(expected,1000 if epoch==0 else 60)
    try:
        # Sequential enrollment respects the real ten-per-15-minute source limit.
        # All admitted clients subsequently execute the same phases concurrently.
        ready=[]
        for index in range(args.clients):
            root=base/str(index)
            for name in ['data/keyrings','state','config','cache','runtime','control']:(root/name).mkdir(parents=True,mode=0o700)
            env={k:v for k,v in os.environ.items() if k in ['PATH','HOME','LANG','LC_ALL','LD_LIBRARY_PATH']}
            env.update({k:str(root/v) for k,v in [('XDG_DATA_HOME','data'),('XDG_STATE_HOME','state'),('XDG_CONFIG_HOME','config'),('XDG_CACHE_HOME','cache'),('XDG_RUNTIME_DIR','runtime')]})
            env.update({'NDS_FLEET_ROOT':str(root),'NDS_FLEET_INDEX':str(index),'NDS_FLEET_COUNT':str(args.clients),'NDS_FLEET_SOCKET':str(base/'control.sock'),'NDS_FLEET_TOKEN_SOCKET':str(base/'session.sock'),'NDS_FIXTURE_RECEIPT':str(args.fixture),'NDS_FLEET_SOURCE':'unknown' if dirty else source})
            log=(args.output/f'supervisor-{index}.log').open('wb')
            try:processes.append(subprocess.Popen(['dbus-run-session','--',sys.executable,__file__,'--worker',str(root),executable,str(index),str(args.clients),str(args.output)],env=env,stdout=log,stderr=log,start_new_session=True))
            finally:log.close()
            ready.append(connect(index,0));event('enrolled',clients=len(ready))
        assert len({r['device'] for r in ready})==args.clients
        assert len({(r['user'],r['tenant']) for r in ready})==1
        send(0,'seed');seed=read(0);assert seed['cursor']==1057;event('seeded',repositories=1024)
        uniform(all_clients('inspect',updated=False,offline=False))
        unchanged=all_clients('unchanged');assert all(x['unchanged'] and x['cursor']==1057 for x in unchanged)
        all_clients('race');all_clients('drain');all_clients('drain')
        for index in range(args.clients):send(index,'resolve');assert read(index)['resolved']
        uniform(all_clients('inspect',updated=True,offline=False))
        mode('offline');all_clients('offline')
        all_clients('stop')
        for connection in sockets.values():connection.close()
        sockets.clear()
        # Supervisors keep their real credential services alive while each NDS
        # process is replaced. Accept restart connections in any order.
        restored={}
        while len(restored)<args.clients:
            check()
            try:connection,_=listener.accept()
            except socket.timeout:continue
            connection.settimeout(1)
            hello=receive(connection,'restart',30)
            index=hello['index'];assert hello['epoch']==1 and index not in restored
            sockets[index]=connection;send(index,'initialize');value=read(index,60)
            assert value==ready[index];restored[index]=value
        event('cold_offline_restored',clients=args.clients)
        mode('online');all_clients('drain');final=all_clients('inspect',updated=True,offline=True);uniform(final)
        for index in range(1,args.clients):send(index,'finish');assert read(index)['finished']
        for index in range(1,args.clients):assert processes[index].wait(timeout=10)==0
        send(0,'finish');assert read(0)['finished'];assert processes[0].wait(timeout=10)==0
        captured=[]
        for path in sorted(args.output.glob('client-*.log.gz')):
            sequence=0;events=0;instance=None
            with gzip.open(path,'rt') as log:
                for line in log:
                    if len(line)>65536:raise RuntimeError('Log record exceeded its bound')
                    try:value=json.loads(line)
                    except json.JSONDecodeError:continue
                    if not isinstance(value,dict) or value.get('service.name')!='nds-fleet-acceptance':continue
                    assert value['producer.sequence']==sequence+1
                    sequence=value['producer.sequence'];events+=1
                    instance=instance or value['producer.instance_id'];assert instance==value['producer.instance_id']
                    assert value['source.commit']==('unknown' if dirty else source)
                    assert value['event.name'] not in ['logging.event.rejected','logging.fields.rejected']
            assert events>0
            captured.append({'file':path.name,'events':events,**json.loads(path.with_name(path.name.replace('.log.gz','-capture.json')).read_text())})
        proof={'captured':captured,'source':source,'dirty_source':dirty,'clients':args.clients,'repositories':1024,'owners':32,'native_processes':args.clients*2,'final':final[0],'phases':history,'scope':'Real Rust clients, separate Secret Service/SQLite, genuine restored fixture session, real HTTP/PostgreSQL; generated catalog inputs, not GitHub-provider acceptance.'}
        (args.output/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n');event('complete',clients=args.clients)
    finally:
        for connection in sockets.values():connection.close()
        listener.close()
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGTERM)
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
        # This supervisor explicitly owns the fresh fixture's test data.
        Path(receipt['stop_marker']).touch()

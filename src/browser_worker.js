// The composition root exports exactly these typed journal entrypoints from its
// WASM bundle. This worker never receives credential material or arbitrary SQL.
let module,scope,busy=false;
self.onmessage=async({data})=>{
  if(busy){self.postMessage({id:data.id,error:'vault_busy'});return;}
  busy=true;
  const controller=new AbortController();
  let timer;
  async function locked(operation){
    timer=setTimeout(()=>controller.abort(),1000);
    return navigator.locks.request('nds-replica:'+scope,{signal:controller.signal},async()=>{
      clearTimeout(timer);return operation();
    });
  }
  try {
    if(data.action==='initialize') {
      const url=new URL(data.module);
      if(module||url.origin!==location.origin||!url.pathname.endsWith('.js')||url.search||url.hash||!/^[a-f0-9]{64}$/.test(data.scope))throw new Error();
      scope=data.scope;module=await import(url.href);await module.default();
      await locked(()=>module.nds_journal_open(scope));
      self.postMessage({id:data.id,result:'ready'});
    } else if(data.action==='execute'&&module&&typeof data.command==='string'&&data.command.length<=8*1024*1024) {
      const result=await locked(async()=>{
        await module.nds_journal_resume();
        try{return module.nds_journal_execute(data.command);}
        finally{module.nds_journal_pause();}
      });
      self.postMessage({id:data.id,result});
    } else throw new Error();
  } catch {
    self.postMessage({id:data.id,error:controller.signal.aborted?'vault_busy':'vault_dependency_unavailable'});
    // A trap or failed pause may retain a native SQLite connection. Terminate
    // this owned realm so OPFS releases handles before any later attempt.
    if(!controller.signal.aborted)self.close();
  } finally {clearTimeout(timer);busy=false;}
};

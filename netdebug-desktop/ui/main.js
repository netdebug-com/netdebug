const { invoke } = window.__TAURI__.tauri;

let greetInputEl;
let greetMsgEl;


async function update_table(table) {
  var table = document.querySelector("#keys-table");
  var old_table_body = document.querySelector("#keys-table-body");
  old_table_body.innerHTML = '';
  let keys = await invoke('dump_connection_keys');
  if (keys.length == 0) {
    var row = old_table_body.insertRow(); 
    row.insertCell().textContent = count;
    row.insertCell().textContent = "No flows -- really!?";
  } else {
    var count = 0;
    keys.forEach(k => {
      var row = old_table_body.insertRow(); 
      count = count +1;
      row.insertCell().textContent = count;
      row.insertCell().textContent = k;
    });
  }
}


window.addEventListener("DOMContentLoaded", () => {
  window.setInterval(update_table, 500);
});

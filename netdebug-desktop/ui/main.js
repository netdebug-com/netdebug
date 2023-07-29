const { invoke } = window.__TAURI__.tauri;

var interval = null;

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

function toggleInterval() {
  var button = document.querySelector("#pause-button");
  if (interval == null) {
    interval = window.setInterval(update_table, 500);
    console.log("Enabling updates: new interval=", interval);
    button.textContent = "Pause Updates";
  } else {
    clearInterval(interval);
    interval = null;
    console.log("Pausing updates");
    button.textContent = "Enable Updates";
  }
}


window.addEventListener("DOMContentLoaded", () => {
  toggleInterval();
  document.getElementById("pause-button").addEventListener("click", toggleInterval);
});

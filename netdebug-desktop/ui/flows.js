var interval = null

// with double-buffering fakery
async function update_table (table) {
  let flows = await window.parent.invoke('dump_connection_keys')
  let keys = Object.keys(flows)
  console.log('Flows = ', flows, 'keys=', keys)
  var table1 = document.querySelector('#keys-table1')
  var table2 = document.querySelector('#keys-table2')
  var old_table_body
  // only update the hidden table
  if (table1.style.display == 'none') {
    old_table_body = document.querySelector('#keys-table-body1')
  } else {
    old_table_body = document.querySelector('#keys-table-body2')
  }
  old_table_body.innerHTML = ''
  if (keys.length == 0) {
    var row = old_table_body.insertRow()
    row.insertCell().textContent = count
    row.insertCell().textContent = 'No flows -- really!?'
  } else {
    var count = 0
    keys.forEach(k => {
      var row = old_table_body.insertRow()
      count = count + 1
      row.insertCell().textContent = count
      row.insertCell().textContent = k
    })
  }
  if (table1.style.display == 'none') {
    table1.style.display = 'inline'
    table2.style.display = 'none'
  } else {
    table1.style.display = 'none'
    table2.style.display = 'inline'
  }
}

function toggleInterval () {
  var button = document.querySelector('#pause-button')
  if (interval == null) {
    interval = window.setInterval(update_table, 500)
    console.log('Enabling updates: new interval=', interval)
    button.textContent = 'Pause Updates'
  } else {
    clearInterval(interval)
    interval = null
    console.log('Pausing updates')
    button.textContent = 'Enable Updates'
  }
}

window.addEventListener('DOMContentLoaded', () => {
  toggleInterval()
  document
    .getElementById('pause-button')
    .addEventListener('click', toggleInterval)
})
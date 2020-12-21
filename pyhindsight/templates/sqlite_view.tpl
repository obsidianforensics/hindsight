% include('templates/header.tpl')

<div id='sqlite-viewer'></div>

<script type='module'>
  import SqliteView from '/static/web_modules/sqlite-view.js';

  const viewer = new SqliteView('sqlite-viewer');
  viewer.load('/sqlite');
</script>

<style>
  .sqlview-table-container table {
    border-collapse: collapse;
  }
  .sqlview-table-container table td {
    border: 1px solid lightgrey;
  }
  .sqlview-table-container table th, .sqlview-table-container table td:first-child {
    border-left: none;
  }
  .sqlview-table-container table th, .sqlview-table-container table td:last-child {
    border-right: none;
  }
</style>

% include('templates/footer.tpl')

window.$ = window.jQuery = require('jquery');
window.c3 = require("c3");
window.SparkMD5 = require("spark-md5");
$.fn.datetimepicker = require('eonasdan-bootstrap-datetimepicker');

// CSS
require('./npm.scss');
require("nvd3/build/nv.d3.min.css");
require("c3/c3.min.css");
require("../rules/static/rules/static.css");
require("../rules/static/rules/jquery-ui.min.css");
require("patternfly/dist/css/patternfly.css");
require("patternfly/dist/css/patternfly-additions.css");
require("../scss/_styles.scss");

// JS
require("../node_modules/patternfly/dist/js/patternfly.js");
require("bootstrap");
require("../node_modules/patternfly-bootstrap-treeview/dist/bootstrap-treeview.js");
require("jquery-knob");
require("jquery-ui");
require("jquery-ui/ui/widgets/sortable");
require("jquery-ui/ui/disable-selection");
require("d3");
require("nvd3");
require("../node_modules/blueimp-file-upload/js/jquery.fileupload.js");
require("../rules/static/js/scirius.js");

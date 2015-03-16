function prepare_rule_details() {
    $(".msg").click(function( event ) {
        if ($(this).find(".detail").length) {
            $(this).find(".detail").slideUp(
                function() {
                    $(this).remove();
                }
            );
        } else {
            sid = $( this ).parent().find("a").html();
            $.ajax(
                {
                        type:"GET",
                        url:"/rules/rule/"+sid,
                        success: function(data) {
                            mylink = $('a').filter(function(index) { return $(this).text() == data.sid; });
                            mytd = mylink.parent().parent().find(".msg");
                            mytd.append("<div class='detail'>" + data.highlight_content + "</div>");
                            mytd.find(".detail").slideDown();
                        },
                }
            );
        }
    });
}

$( 'document' ).ready(function() {
        prepare_rule_details();
});

function draw_timeline(from_date, hosts, filter) {

        esurl = "/rules/es?query=timeline&from_date=" + from_date + "&hosts=" + hosts.join()
        if (filter) {
            esurl = esurl + "&filter=" + filter;
        }
        $.ajax(
                        {
                        type:"GET",
                        url:esurl,
                        success: function(data) {
			    $("#timeline span").hide();
                            nv.addGraph(function() {
		            /* starting from 4 hosts multibar is unreadable */
                            if (hosts.length > 3) {
                              var chart = nv.models.lineChart()
                                            .margin({left: 100})  //Adjust chart margins to give the x-axis some breathing room.
                                            .useInteractiveGuideline(true)  //We want nice looking tooltips and a guideline!
                                            .transitionDuration(350)  //how fast do you want the lines to transition?
                                            .showLegend(true)       //Show the legend, allowing users to turn on/off line series.
                                            .showYAxis(true)        //Show the y-axis
                                            .showXAxis(true)        //Show the x-axis
                              ;
                              } else {
                            multigraph = false;
                            if (hosts.length > 1) {
                                    multigraph = true;
                            }
                            var chart = nv.models.multiBarChart()
                                .transitionDuration(350)
                                .reduceXTicks(true)   //If 'false', every single x-axis tick label will be rendered.
                                .rotateLabels(0)      //Angle to rotate x-axis labels.
                                .showControls(multigraph)   //Allow user to switch between 'Grouped' and 'Stacked' mode.
                                .groupSpacing(0.1)    //Distance between each group of bars.
                                ;
                               }
                                chart.xAxis.tickFormat(function(d) {
                                    return d3.time.format('%m/%d %H:%M')(new Date(d))
                                });

                                chart.yAxis
                                .tickFormat(d3.format(',.1f'));

                                var end_interval = new Date().getTime();
                                var sdata = []
                                for (hi = 0; hi < hosts.length; hi++) {
                                        gdata = []
                                        var starti = 0;
                                        var iter = 0;
                                        entries = data[hosts[hi]]['entries']
                                        var interval = parseInt(data['interval']);
                                        for (inter = parseInt(data['from_date']); inter < end_interval; inter = inter + interval) {
                                            found = false;
                                            for (i = starti; i < entries.length; i++) {
                                                if (Math.abs(entries[i]["time"] - inter) <= interval/2) {
                                                    gdata.push({x: inter, y: entries[i]["count"]});
                                                    found = true;
                                                    starti = i + 1;
                                                    break;
                                                }
                                            }
                                            if (found == false) {
                                                    gdata.push({x: inter, y: 0});
                                            }
                                        }
                                        sdata.push(
                                        {
                                            values: gdata,
                                            key: hosts[hi],
                                            //color: '#AD9C9B',  //color - optional: choose your own line color.
                                            //area: true
                                        }
                                        );
                                }
                                d3.select('#timeline svg')
                                        .datum(sdata)
                                        .call(chart);

                                nv.utils.windowResize(function() { chart.update() });
                                return chart;
                        });
                },
        });
}

function draw_circle(from_date, hosts, filter) {
        esurl = "/rules/es?query=rules_per_category&from_date=" + from_date + "&hosts=" + hosts.join()
        if (filter) {
            esurl = esurl + "&filter=" + filter;
        }
        $.ajax(
         {
         type:"GET",
         url:esurl,
         success: function(data) {
             var margin = 20,
                 diameter = 600;
             
             var color = d3.scale.linear()
                 .domain([-1, 2])
                 .range(["rgb(179,191,202)", "rgb(74,143,202)"])
                 .interpolate(d3.interpolateHcl);

             var pack = d3.layout.pack()
                 .padding(2)
                 .size([diameter - margin, diameter - margin])
                 .value(function(d) { return d.doc_count; })
		 .children(function(d) { return d.rule ? d.rule.buckets : undefined; })
             
             var svg = d3.select("#circles").append("svg")
                 .attr("width", diameter)
                 .attr("height", diameter)
               .append("g")
                 .attr("transform", "translate(" + diameter / 2 + "," + diameter / 2 + ")");
            
	       root = data
               var focus = root,
                   nodes = pack.nodes(root),
                   view;
             
               var circle = svg.selectAll("circle")
                   .data(nodes)
                   .enter().append("circle")
                   .attr("class", function(d) { return d.parent ? d.children ? "node" : "node node--leaf" : "node node--root"; })
                   .style("fill", function(d) { return d.children ? color(d.depth) : null; })
                   .on("click", function(d) { if (focus !== d) zoom(d), d3.event.stopPropagation(); });
            
               $('circle').tipsy({ 
                 gravity: 'w', 
                 html: true, 
                 title: function() {
                   var d = this.__data__;
                   return d.key ? d.key : "Unknown"; 
                 }
               });

/*
               var text = svg.selectAll("text")
                   .data(nodes)
                 .enter().append("text")
                   .attr("class", "d3-label")
                   .style("fill-opacity", function(d) { return d.parent === root ? 1 : 0; })
                   .style("display", function(d) { return d.parent === root ? null : "none"; }) 
                   .text(function(d) { return d.key ? d.key : "Unknown"; });
		   */
             
               var node = svg.selectAll("circle,text");
             
               d3.select("circle")
                   .style("background", color(-1))
                   .on("click", function() { zoom(root); });
             
               zoomTo([root.x, root.y, root.r * 2 + margin]);
             
               function zoom(d) {
                 var focus0 = focus; focus = d;
             
	         if (d.children == undefined) {
                     window.open("/rules/rule/pk/" + d.key,"_self");
		 }
                 var transition = d3.transition()
                     .duration(d3.event.altKey ? 7500 : 750)
                     .tween("zoom", function(d) {
                       var i = d3.interpolateZoom(view, [focus.x, focus.y, focus.r * 2 + margin]);
                       return function(t) { zoomTo(i(t)); };
                     });
            /* 
                 transition.selectAll("text")
                   .filter(function(d) { return d.parent === focus || this.style.display === "inline"; })
                     .style("fill-opacity", function(d) { return d.parent === focus ? 1 : 0; })
                     .each("start", function(d) { if (d.parent === focus) this.style.display = "inline"; })
                     .each("end", function(d) { if (d.parent !== focus) this.style.display = "none"; });
		     */
               }
             
               function zoomTo(v) {
                 var k = diameter / v[2]; view = v;
                 node.attr("transform", function(d) { return "translate(" + (d.x - v[0]) * k + "," + (d.y - v[1]) * k + ")"; });
                 circle.attr("r", function(d) { return d.r * k; });
               }
             
             d3.select(self.frameElement).style("height", diameter + "px");
 	},
        });
}

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
                              var chart = nv.models.lineChart()
                                            .margin({left: 100})  //Adjust chart margins to give the x-axis some breathing room.
                                            .useInteractiveGuideline(true)  //We want nice looking tooltips and a guideline!
                                            .transitionDuration(350)  //how fast do you want the lines to transition?
                                            .showLegend(true)       //Show the legend, allowing users to turn on/off line series.
                                            .showYAxis(true)        //Show the y-axis
                                            .showXAxis(true)        //Show the x-axis
                              ;
                              /*
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
                                */
                                chart.xAxis.tickFormat(function(d) {
                                    return d3.time.format('%m/%d %H:%M')(new Date(d))
                                });

                                chart.yAxis
                                .tickFormat(d3.format(',.1f'));

                                sdata = []
                                for (hi = 0; hi < hosts.length; hi++) {
                                        gdata = []
                                        entries = data[hosts[hi]]['entries']
                                        for (i = 0; i < entries.length; i++) {
                                                gdata.push({x: entries[i]["time"], y: entries[i]["count"]});
                                        }
                                        sdata.push(
                                        {
                                            values: gdata,
                                            key: hosts[hi],
                                            //color: '#AD9C9B',  //color - optional: choose your own line color.
                                            area: true
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

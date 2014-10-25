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

var modalPopup = (function()
	var self = {};
	var popup;
	/// Universal Modal Popup
	/// @param title - string or bool (Setting to false will remove title bar)
	/// @param content - set of elements ( $("<p>Example text</p>") )
	/// @param width - int
	/// @param btns - array of button objects with optional methods ( [{text:"Ok", trigger:function(){}}, {text:"Dismiss", trigger:function(){}}] )
	/// @param open - function callback on dialog open
	/// @param close - function callback on dialog close
	self.createWindow = function(title, content, width, height, btns, open, close, closeOnEsc)
		// Hide title bar if we don't provide a title. Keep in mind that this also hides the close button.
		var dialogClassName = (title) ? "modalPopup" : "modalPopup noTitle";
		// Decode entities.
		var nTitle = (typeof title === "string") ? $("<i/>").html(title).text() : title;
		open = open || function(){};
		close = close || function(){};
		var btnsIn = btns || [];
		var buttons = [];
		var escToClose = typeof closeOnEsc !== 'undefined' ? closeOnEsc : true;
		$.each(btnsIn, function(i) {
			var trigger = this.trigger || function(){};
			// Decode entities.
			var btnText = $("<i/>").html(this.text).text();
			buttons[i] = {
				"text" : btnText,
				"class" : this.className,
				"click" : function() {
					trigger();
					$(this).dialog("destroy").remove();
		// The dialog needs to bind to a DOM element.
		// We create that element here.
		popup = $("<div></div>")
			.append(content)
			.dialog({
				modal : true,
				resizable : false,
				dialogClass : dialogClassName,
				width : width,
				height : height,
				title : nTitle,
				draggable : false,
				buttons : buttons,
				closeOnEscape: escToClose,
				open : function() {
					open();
					$(this).parent().find("button.primary").focus();
				close : function() {
					close();
					$(this).dialog("destroy").remove();
	self.loadPage = function(title, url,  width, height, callback, open, close, closeOnEsc) {
        var width = width || 900;
        var height = height || 700;
        var callback = callback || function() {};
	var open = open || function(){};
        var close = close || function() {};
	var escToClose = typeof closeOnEsc !== 'undefined' ? closeOnEsc : true;
        $.get(url, function(data) {
          	$("#dialog").html(data);
          	popup = $("<div></div>")
			.append(data)
			.dialog({
				modal : true,
				resizable : false,
				width : width,
				height : height,
				title : title,
				draggable : false,
				closeOnEscape: escToClose,
				open : function() {
					open();
				close : function() {
					$(this).dialog("destroy").remove();
					close();
        callback();
       }); 		
	/// Universal Modal Popup
	/// Call this method to dismiss the modal-window
	self.destroyWindow = function(){
		$(popup).dialog("destroy").remove();
	return self;

/**
 * slideButton jQuery Plug-in
 *
 * Copyright 2013 Novatel Wireless (http://www.nvtl.com/)
 *
 * Date:   2014-04-29
 * Rev:    1.2.03
 * Author: John C. Scott <joscott@nvtl.com>
 */
(function($){
	var VERSION  = "1.2.03";
	var DATANAME = "slideButton";

	// set valid field types
	var allow = ":checkbox, :radio";

	var defaults = {
		duration          : 200,     // the speed of the animation
		easing            : "swing", // the easing animation to use
		labelOn           : "ON",    // the text to show when toggled on
		labelOff          : "OFF",   // the text to show when toggled off
		resizeHandle      : "auto",  // determines if handle should be resized
		resizeContainer   : "auto",  // determines if container should be resized
		enableDrag        : true,    // determines if we allow dragging
		dragThreshold     : 5,       // determines click to drag point accuracy, lower being more accurate
		enableFx          : true,    // determines if we show animation
		allowRadioUncheck : false,   // determine if a radio button should be able to be unchecked
		clickOffset       : 120,     // if milliseconds between a mousedown & mouseup event this value, considered a mouse click
		showLoader        : true,    // show loader when slideButton changes
		fadeLoader        : true,    // fade loader when removing

		// define the class statements
		className         : "",
		classContainer    : "slidebutton-container",
		classLoader       : "slidebutton-loader",
		classDisabled     : "slidebutton-disabled",
		classFocus        : "slidebutton-focus",
		classLabelOn      : "slidebutton-label-on",
		classLabelOff     : "slidebutton-label-off",
		classHandle       : "slidebutton-handle",
		classHandleMiddle : "slidebutton-handle-middle",
		classHandleRight  : "slidebutton-handle-right",
		classHandleActive : "slidebutton-active-handle",
		classPaddingLeft  : "slidebutton-padding-left",
		classPaddingRight : "slidebutton-padding-right",

		// event handlers
		init    : null, // callback that occurs when a slideButton is initialized
		change  : null, // callback that occurs when the button state is changed
		click   : null, // callback that occurs when the button is clicked
		disable : null, // callback that occurs when the button is disabled/enabled
		destroy : null  // callback that occurs when the button is destroyed
	};

	var ON       = defaults.labelOn;
	var OFF      = defaults.labelOff;

	/**
	 * Define slideButton function jQuery plugin
	 * @param {String} method
	 *
	 * Methods are called like this.
	 *
	 * $("#id").slideButton("toggle");
	 *
	 * The method parameter can be followed by any number of arguments.
	 */
	$.fn.slideButton = function(method)
	{
		var input = this;
		var args = arguments;
		return input.each(function() {
			if (methods[method]) {
				return methods[method].apply(input, Array.prototype.slice.call(args, 1));
			} else if ( typeof method === "object" || !method) {
				return methods.init.apply(input, args);
			} else {
				$.error("Method " + method + " does not exist in jQuery.fn.slideButton");
			}
		});
	};

	// Public Methods

	var methods = {

		version : function() {
			return VERSION;
		},

		init : function(options)
		{
			var input = this;
			var $input = $(input);
			var data = $input.data(DATANAME);

			// When clicking on label, do nothing.
			var $inputLabel = $('label[for="' + $input.attr("id") + '"]');
			$inputLabel.click(function(e) { e.preventDefault(); });

			if(!data) {
				var id = 0;
				// make a copy of the merged defaults & options
				var o = $.extend(true, {}, defaults, options);

				// check to see if we're using the default labels
				var bDefaultLabelsUsed = (o.labelOn == ON && o.labelOff == OFF);

				// only do for checkboxes buttons, if matches inside that node
				if( !$input.is(allow) ) {
					return $input.find(allow).slideButton(options);
				}

				// if using the "auto" setting, then don't resize handle or container if using the default label (since we'll trust the CSS)
				if( o.resizeHandle == "auto" ) o.resizeHandle = !bDefaultLabelsUsed;
				if( o.resizeContainer == "auto" ) o.resizeContainer = !bDefaultLabelsUsed;

				$input
					// create the wrapper code
					.wrap('<div class="' + $.trim(o.classContainer + ' ' + o.className) + '" />')
					.after(
							'<div class="' + o.classHandle + '"><div class="' + o.classHandleRight + '"><div class="' + o.classHandleMiddle + '" /></div></div>'
						+ '<div class="' + o.classLabelOff + '"><div>'+ o.labelOff + '</div></div>'
						+ '<div class="' + o.classLabelOn + '"><div>' + o.labelOn   + '</div></div>'
						+ '<div class="' + o.classPaddingLeft + '"></div><div class="' + o.classPaddingRight + '"></div>'
					);

				var $offlabel = $input.siblings("." + o.classLabelOff);
				var $onlabel  = $input.siblings("." + o.classLabelOn);

				$input.data(DATANAME, {
					$container  : $input.parent(),
					$handle     : $input.siblings("." + o.classHandle),
					$offlabel   : $offlabel,
					$offspan    : $offlabel.children("div"),
					$onlabel    : $onlabel,
					$onspan     : $onlabel.children("div"),
					$loader     : $('<div class="' + o.classLoader + '"></div>'),
					id          : ++id,
					loading     : false,
					disabled    : false,
					width       : {},
					handleRight : 0,
					mouse       : { dragging: false, clicked: null },
					dragStart   : { position: null, offset: null, time: null },
					options     : o
				});

				// set up toggle handle
				handleSetup.call(input);

				// establish event bindings
				attachEvents.call(input);

				// if the field is disabled, mark it as such
				if( $input.is(":disabled") ) methods.disable.call(input, true);

				// IE handling
				ieSpecialBehaviors.call(input);

				// run the init callback
				if( $.isFunction(o.init) ) o.init.apply(input, [$input, options]);
			}
		},

		toggle : function(t)
		{
			var $input = $(this);
			var toggle = (arguments.length > 0) ? t : !$input.prop("checked");
			$input.prop("checked", toggle).trigger("change");
		},

		// instantiates slideButton and adds a generic
		// REST "change" callback to the slideButton object
		ajaxToggle : function(options)
		{
			var input = this;
			var $input = $(input);

			// Init slideButton.
			methods.init.call(input, options);
			var data = $input.data(DATANAME);
			var options = data.options;

			options.change = function($input){
				var url = ($input[0].checked) ? options.checkUrl : options.uncheckUrl;
				if(options.showLoader) methods.addLoader.call(input);
				$.ajax({
					url : url,
					type : "POST",
					data : options.data,
					dataType : "json",
					success : function(data, textStatus, xhr) {
						// If no network connected, success event still occurs.
						// We need to implicitly see an xhr.status greater than 0 to know we've actually made contact.
						if ( (xhr.readyState == 4 ) && (xhr.status == 0) ) methods.undo.call(input);
					},
					error : function(xhr, textStatus, errorThrown){
						methods.undo.call(input);
					},
					complete : function(xhr, textStatus) {
						if(options.showLoader) methods.removeLoader.call(input, options.fadeLoader);
					}
				});
			};
		},

		// disable/enable the control
		disable : function(t)
		{
			var input = this;
			var $input = $(input);
			var data = $input.data(DATANAME);
			var options = data.options;
			var toggle = (arguments.length > 0) ? t : !data.disabled;
			// mark the control disabled
			data.disabled = toggle;
			// mark the input disabled
			$input.prop("disabled", toggle);
			// set the diabled styles
			data.$container[toggle ? "addClass" : "removeClass"](options.classDisabled);
			// run callback
			if( $.isFunction(options.disable) ) options.disable.apply(input, [disabled, $input, options]);
		},

		// add loader
		addLoader : function()
		{
			var data = $(this).data(DATANAME);
			data.$loader.prependTo(data.$container).show();
			data.loading = true;
		},

		// remove loader
		removeLoader : function(fade)
		{
			var data = $(this).data(DATANAME);
			if (fade == false){
				data.$loader.detach();
				data.loading = false;
			} else {
				data.$loader.fadeOut("slow", function(){
					$(this).detach();
					data.loading = false;
				});
			};
		},

		// repaint the button
		repaint : function()
		{
			positionHandle.call(this);
		},

		// reset the button to its initial state
		undo : function()
		{
			var input = this;
			var $input = $(input);
			$input.prop("checked", !$input[0].checked);
			methods.repaint.call(input);
		},

		// this will destroy the slideButton object
		destroy : function()
		{
			var input = this;
			var $input = $(this);
			var data = $input.data(DATANAME);
			var options = data.options;
			// remove behaviors
			$([$input[0], data.$container[0]]).unbind(".slideButton");
			$(document).unbind(".slideButton");
			// move the checkbox to it's original location
			data.$container.after($input).remove();
			// kill the reference
			$input.removeData(DATANAME);
			// run callback
			if( $.isFunction(options.destroy) ) options.destroy.apply(input, [$input, options]);
		}
	};

	// Private Methods

	var positionHandle = function(animate)
	{
		var $input = $(this);
		var data = $input.data(DATANAME);
		var options = data.options;
		var checked = $input[0].checked;
		var x = (checked) ? data.handleRight : 0;
		var animate = (arguments.length > 0) ? arguments[0] : true;

		if( animate && options.enableFx ){
			data.$handle.stop().animate({left: x}, options.duration, options.easing);
			data.$onlabel.stop().animate({width: x + 4}, options.duration, options.easing);
			data.$onspan.stop().animate({marginLeft: x - data.handleRight}, options.duration, options.easing);
			data.$offspan.stop().animate({marginRight: -x}, options.duration, options.easing);
		} else {
			data.$handle.css("left", x);
			data.$onlabel.css("width", x + 4);
			data.$onspan.css("marginLeft", x - data.handleRight);
			data.$offspan.css("marginRight", -x);
		}
	};

	var getDragPos = function(e)
	{
		return e.pageX || ((e.originalEvent.changedTouches) ? e.originalEvent.changedTouches[0].pageX : 0);
	};

	var handleSetup = function()
	{
		var data = $(this).data(DATANAME);
		var options = data.options;
		var width = data.width;

		// if we need to do some resizing, get the widths only once
		if( options.resizeHandle || options.resizeContainer ){
			width.onspan = data.$onspan.outerWidth();
			width.offspan = data.$offspan.outerWidth();
		}

		// automatically resize the handle
		if( options.resizeHandle ){
			width.handle = Math.min(width.onspan, width.offspan);
			data.$handle.css("width", width.handle);
		} else {
			width.handle = data.$handle.width();
		}

		// automatically resize the control
		if( options.resizeContainer ){
			width.container = (Math.max(width.onspan, width.offspan) + width.handle + 20);
			data.$container.css("width", width.container);
			// adjust the off label to match the new container size
			data.$offlabel.css("width", width.container - 5);
		} else {
			width.container = data.$container.width();
		}

		data.handleRight = width.container - width.handle - 6;

		// place the buttons in their default location
		positionHandle.call(this, false);
	};

	var attachEvents = function()
	{
		var input = this;
		var $input = $(input);
		var data = $input.data(DATANAME);
		var options = data.options;

		var localMouseMove = function(e) {
			onGlobalMove.call(input, e);
		};

		var localMouseUp = function(e) {
			onGlobalUp.call(input, e);
			$(document).unbind("mousemove.slideButton touchmove.slideButton", localMouseMove);
			$(document).unbind("mouseup.slideButton touchend.slideButton", localMouseUp);
		};

		attachToggleEvents.call(input);

		data.$container.bind("mousedown.slideButton touchstart.slideButton", function(e) {
			onMouseDown.call(input, e);
			if(options.enableDrag) $(document).bind("mousemove.slideButton touchmove.slideButton", localMouseMove);
			$(document).bind("mouseup.slideButton touchend.slideButton", localMouseUp);
		});
	};

	var onGlobalMove = function(e)
	{
		var input = this;
		var $input = $(input);
		var data = $input.data(DATANAME);
		var options = data.options;

		if (!(!data.disabled && data.mouse.clicked)) return;
		var x = getDragPos(e);
		e.preventDefault();
		if (!data.mouse.dragging && (Math.abs(data.dragStart.position - x) > options.dragThreshold)) {
			data.mouse.dragging = true;
		}
		onDragMove.call(input, e, x);
	};

	var onGlobalUp = function(e)
	{
		var input = this;
		var $input = $(input);
		var data = $input.data(DATANAME);

		if (!data.mouse.clicked) return;
		var x = getDragPos(e);
		e.preventDefault();
		onDragEnd.call(input, e, x);
		return false;
	};

	var onMouseDown = function(e)
	{
		var input = this;
		var $input = $(input);
		var data = $input.data(DATANAME);
		var options = data.options;

		// abort if disabled or loading or allow clicking the input to toggle the status (if input is visible)
		if( $(e.target).is(allow) || data.disabled || data.loading || (!options.allowRadioUncheck && $input.is(":radio:checked")) ) return;

		e.preventDefault();
		data.mouse.clicked = data.$handle;
		data.dragStart.position = getDragPos(e);
		data.dragStart.time = (new Date()).getTime();
		data.dragStart.offset = data.dragStart.position - (parseInt(data.$handle.css("left"), 10) || 0);
	};

	var onDragMove = function(e, x)
	{
		var input = this;
		var $input = $(input);
		var data = $input.data(DATANAME);
		var options = data.options;

		// if we haven't clicked on the container, cancel event
		if(data.mouse.clicked != data.$handle) return;

		if( x != data.dragStart.offset ){
			data.mouse.dragging = true;
			data.$container.addClass(options.classHandleActive);
		}

		// make sure number is between 0 and 1
		var pct = Math.min(1, Math.max(0, (x - data.dragStart.offset) / data.handleRight));

		data.$handle.css("left", pct * data.handleRight);
		data.$onlabel.css("width", pct * data.handleRight + 4);
		data.$offspan.css("marginRight", -pct * data.handleRight);
		data.$onspan.css("marginLeft", -(1 - pct) * data.handleRight);
	};

	var onDragEnd = function(e, x)
	{
		var input = this;
		var $input = $(input);
		var data = $input.data(DATANAME);
		var options = data.options;

		// if we haven't clicked on the container, cancel event
		if(data.mouse.clicked != data.$handle) return;

		// track if the value has changed
		var changed = true;

		// if not dragging or click time under a certain millisecond, then just toggle
		if( !data.mouse.dragging || (((new Date()).getTime() - data.dragStart.time) < options.clickOffset ) ){
			var checked = $input.prop("checked");
			$input.prop("checked", !checked);

			// run callback
			if( $.isFunction(options.click) ) options.click.apply(input, [!checked, $input, options]);
		} else {
			//var x = getDragPos(e);
			var pct = (x - data.dragStart.offset) / data.handleRight;
			var checked = (pct >= 0.5);

			// if the value is the same, don't run change event
			if( $input[0].checked == checked ) changed = false;

			$input.prop("checked", checked);
		}

		// remove the active handler class
		data.$container.removeClass(options.classHandleActive);
		data.mouse.clicked =  null;
		data.mouse.dragging = null;

		// run any change event for the element
		if( changed ) {
			$input.trigger("change");
		// if the value didn't change, just reset the handle
		} else {
			positionHandle.call(input);
		}
	};

	var attachToggleEvents = function()
	{
		var input = this;
		var $input = $(input);
		var data = $input.data(DATANAME);
		var options = data.options;

		$input
			.bind("change.slideButton", function() {
				if(data.loading) return false;

				// move handle
				positionHandle.call(input);

				// if a radio element, then we must repaint the other elements in it's group to show them as not selected
				if( $input.is(":radio") ){
					var el = $input[0];

					// try to use the DOM to get the grouped elements, but if not in a form get by name attr
					var $radio = $(el.form ? el.form[el.name] : ":radio[name=" + el.name + "]");

					// repaint the radio elements that are not checked
					$radio.filter(":not(:checked)").slideButton("repaint");
				}

				// run callback
				if( $.isFunction(options.change) ) options.change.apply(input, [$input, options]);
			})

			// if the element has focus, we need to highlight the container
			.bind("focus.slideButton", function(){
				data.$container.addClass(options.classFocus);
 		  })

			// if the element loses focus, we need to clear the highlight from the container
			.bind("blur.slideButton", function(){
				data.$container.removeClass(options.classFocus);
			})

			// if the element is in focus, hitting the enter key (or the default space key) will toggle the switch
			.bind("keyup.slideButton", function(e) {
				if( (e.keyCode == 13) && ($(this).is(":focus")) ) {
					methods.toggle.call(this);
				}
			});

		// if a click event is registered, we must register on the checkbox so it's fired if triggered on the checkbox itself
		if( $.isFunction(options.click) ){
			$input.bind("click.slideButton", function(){
				if(data.loading) return false;
				options.click.apply(input, [$input[0].checked, $input, options]);
			});
		}
	};

	// special behaviors for IE
	var ieSpecialBehaviors = function()
	{
		var $input = $(this);
		var data = $input.data(DATANAME);
		if(navigator.appName == "Microsoft Internet Explorer"){
			// disable text selection in IE, other browsers are controlled via CSS
			data.$container.find("*").addBack().attr("unselectable", "on");
			// IE needs to register to the "click" event to make changes immediately (the change event only occurs on blur)
			$input.bind("click.slideButton", function(){
				if(data.loading) return;
				$input.triggerHandler("change.slideButton");
			});
		}
	};
})(jQuery);
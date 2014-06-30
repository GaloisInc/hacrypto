
var showAllStatus = { 'specs': 
                       {'show': false, 'alllinkid': '#showallspecslink', 'singlelinkclass': '.showspecslink',
	                    'showclass': '.specsdiv', 'showtext': 'Show specs', 'hidetext': 'Hide specs', 
	                    'showalltext': 'Show all specs', 'hidealltext': 'Hide all specs'}, 
	                  'source':
	                   {'show': false, 'alllinkid': '#showallsourcelink', 'singlelinkclass': '.showsourcelink',
		                'showclass': '.sourcediv', 'showtext': 'Show source', 'hidetext': 'Hide source', 
		                'showalltext': 'Show all source', 'hidealltext': 'Hide all source'}
};

function setup() {
	$j('#search-box').val('Search...');

	var initialHash = $j.history.getCurrent();
	if (!processHash(initialHash)) {
		$j('#main-display').load('all-classes.html');
	}
	$j(document).history(function(e,curr,prev) { processHash(curr); });

	var autocompleter = new Autocompleter.Local('search-box', 'search-results', elements_list, {updateElement: selectedAuto, partialChars: 1, fullSearch: true, selector: customSearch});
	
	$j('#search-box').focus(function(event){
		$('search-box').morph('width: 500px; font-size: 20px;', {duration: 0.2});
		$('search-pane').morph('width: 500px; font-size: 20px;', {duration: 0.2});
		$('main-display').morph('opacity: 0.1', {duration: 0.2});
		$('side-bar').morph('opacity: 0.3', {duration: 0.2});
		if ($j('#search-box').val() == 'Search...') {
			$j('#search-box').val('');
		} else if ($j('#search-box').val() != '') {
			setTimeout(function(){ autocompleter.show(); }, 250);
		}
	});

	//On search box lose focus, restore search box (and  small size
	$j('#search-box').blur(function(event){
		$('search-box').morph('width: 150px; font-size: 12px;', {duration: 0.2});
		$('search-pane').morph('width: 200px; font-size: 20px;', {duration: 0.2});
		$('main-display').morph('opacity: 1', {duration: 0.2});
		$('side-bar').morph('opacity: 1', {duration: 0.2});
		if ($j('#search-box').val() == '') {
			$j('#search-box').val('Search...');
		}
	});

	$j(document).bind('keydown', {combi: '/', disableInInput: true}, function() {
		$j('#search-box').focus();
		return false;
	});

	$j(document).bind('keydown', 'esc', function() {
		$j('#search-box').blur();
	});

	$j(document).bind('keydown', {combi: 's', disableInInput: true}, function() {
		$j('#showallspecslink').click();
	});

	$j(document).bind('keydown', {combi: 'c', disableInInput: true}, function() {
		$j('#showallsourcelink').click();
	});

	$j(document).bind('keydown', {combi: 'd', disableInInput: true}, function() {
		switchToType('diagram');
	});

	$j(document).bind('keydown', {combi: 'f', disableInInput: true}, function() {
		switchToType('doc');
	});

}

function switchToType(type) {
	var currentHash = $j.history.getCurrent();
	var parts = currentHash.split(':');
	if (parts.length >= 2) {
		if (parts.length == 2) {
			parts.push(type);
		} else {
			parts[2] = type;
		}
		userLoad(parts);
	}
}

function processHash(hash) {
	var parts = hash.split(':');
	if (parts.length >= 2) {
		if (parts.length == 2) {
			parts.push('doc');
		}
		loadEntity(parts);
		return true;
	}
	return false;
}

function userLoad(parts) {
	$j.history.add(parts.join(':'));
	loadEntity(parts);
}

function loadEntity(parts) {
	var page = parts[2] == 'diagram' ? parts[1] + "-diagram.html" : parts[1] + '.html';
	$j('#main-display').load(page, function() {
		SyntaxHighlighter.highlight();
		$j.each(showAllStatus, function(i,sa) { showAllByStatus(sa); }); //Correctly show all by status
		if ($j('#' + parts.join(':')).length > 0) {
			//TODO - not working
			Effect.ScrollTo('#' + parts.join(':'), {duration: 0.2});
		} else {
			//alert("No such thing: " + parts.join(':'));
		}
	});
	$j('#related').load(parts[1] + '-related.html');
}

function navTo(loc) {
	var parts = loc.split(':');
	if (parts.length >= 2) {
		if (parts.length == 2) {
			parts.push('doc');
		}
		userLoad(parts);
	}
	return false;
}

function toggleShow(id,link,showtext,hidetext) {
	$j(id).toggleClass('invisible');
	if ($j(id).hasClass('invisible')) {
		$j(link).text(showtext);
	} else {
		$j(link).text(hidetext);
	}
	return false;
}

function toggleShowAll(showallid) {
	var sa = showAllStatus[showallid];
	if (!sa) { return false; }
	sa.show = !sa.show;
	showAllByStatus(sa);
	return false;
}

function showAllByStatus(sa) {
	if (!sa) { return false; }
	if (sa.show) {
		//Show all
		$j(sa.alllinkid).text(sa.hidealltext);
		$j(sa.singlelinkclass).text(sa.hidetext);
		$j(sa.showclass).removeClass('invisible');
	} else {
		//Hide all
		$j(sa.alllinkid).text(sa.showalltext);
		$j(sa.singlelinkclass).text(sa.showtext);
		$j(sa.showclass).addClass('invisible');
	}
	return false;
}

function customSearch(instance) {
	var ret       = []; //matches
	var search    = instance.element.value; //User input
	var searchParts = $j.grep(search.split(/\s+/),function(s){ return s.length !== 0; }); //Array of parts, filter for ''
	var originalNormalSearchParts = [];
	var normalSearchParts = [];
	var featureSearchParts = [];
	//Fill the two arrays
	$j.each(searchParts,function(i,s){ if (s.charAt(0) == '.') { featureSearchParts.push(s.substring(1).toLowerCase()); } else { originalNormalSearchParts.push(s.toLowerCase()); } });

	//Allow for class.method searches
	$j.each(originalNormalSearchParts, function(i,s) {
		var index = s.indexOf('.');
		if (index == -1) {
			normalSearchParts.push(s);
		} else {
			var parts = s.split('.');
			normalSearchParts.push(parts[0]);
			if (parts.length > 1) {
				featureSearchParts.push(parts[1]);
			}
		}
	});

	//Recognise a loan '.'
	var hadFeatureSearch = featureSearchParts.length > 0;
	//Filter empty feature searches
	featureSearchParts = $j.grep(featureSearchParts,function(s){ return s.length !== 0; });

	for (var i = 0; i < instance.options.array.length ; i++) {
		var elem = instance.options.array[i]; 
		var elNameLower = elem.name.toLowerCase();

		var match = true;
		var matchRegions = [];
		$j.each(normalSearchParts, function(i,s) { 
			var index = elNameLower.indexOf(s);
			if (index == -1) {
				match = false; 
				return false;
			} else {
				matchRegions.push([index,index+s.length]);	
			}
		});

		if (match) {
			if (normalSearchParts.length !== 0 && !hadFeatureSearch) {
				matchRegions.sort();
				ret.push([matchRegions[0][0], elem.name, "<li id=\"class:" + elem.name + "\">" + annotateMatch(elem.name,matchRegions) + "</li>"]);
			} else if (featureSearchParts.length !== 0 || (hadFeatureSearch && normalSearchParts.length !== 0)) {
				var features = elem.features;
				for (var j=0; j < features.length; j++) {
					var feature = features[j];
					var featureLower = feature.toLowerCase();
					var featureMatch = true;
					var featureMatchRegions = [];
					$j.each(featureSearchParts, function(k,s) {
						var index = featureLower.indexOf(s);
						if (index == -1) {
							featureMatch = false;
							return false;
						} else {
							featureMatchRegions.push([index,index+s.length]);
						}
					});
					if (featureMatch) {
						matchRegions.sort();
						if(featureSearchParts.length === 0) {
							ret.push([matchRegions[0][0], elem.name,
									"<li id=\"class:" + elem.name + ":" + feature + "\">" + annotateMatch(elem.name,matchRegions) + "." + annotateMatch(feature,featureMatchRegions.sort()) + "</li>"]);
						} else {
							featureMatchRegions.sort();	
							ret.push([featureMatchRegions[0][0], matchRegions.length > 0 ? matchRegions[0][0] : 1000,
									  elem.name, feature,
									  "<li id=\"class:" + elem.name + ":doc:" + feature + "\">" + annotateMatch(elem.name,matchRegions) + "." + annotateMatch(feature,featureMatchRegions.sort()) + "</li>"]);
						}
					}
				}
			}
		}
	}

	ret.sort();
	ret = ret.slice(0,instance.options.choices);
	ret = $j.map(ret, function(n) { return n[n.length-1]; });

	return "<ul>" + ret.join('') + "</ul>";
}

function annotateMatch(s,matchedRegions) {
	var lastMatch = 0;
	var annotated = '';
	for (var i=0; i < matchedRegions.length; i++) {
		var match = matchedRegions[i];
		annotated += s.substring(lastMatch,match[0]);
		annotated += '<strong>';
		while (i < (matchedRegions.length-1) && matchedRegions[(i+1)][0] <= match[1]) {
			i++;
		}
		annotated += s.substring(match[0],matchedRegions[i][1]);
		annotated += '</strong>';
		lastMatch = matchedRegions[i][1];
	}
	annotated += s.substring(lastMatch,s.length);
	return annotated;
}

//Do relevant action for selected <li> element
function selectedAuto(selectedElement) {
	if (selectedElement.id) {
		navTo(selectedElement.id);
		$j('#search-box').blur(); 
	}
}
rule SIGNATURE_BASE_Apt_CN_Tetrisplugins_JS : FILE
{
	meta:
		description = "Code and strings of plugins from the Tetris framework loaded by Swid"
		author = "@imp0rtp3"
		id = "83e6fbad-55d6-5229-a17d-8929e0e658f8"
		date = "2020-09-06"
		modified = "2023-12-05"
		reference = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_tetris.yar#L34-L114"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fa77d622584e79c86139b9c0f0b8ff46fc10461d0776e46c93490b6bb667afcf"
		score = 75
		quality = 60
		tags = "FILE"

	strings:
		$a3 = "(0xbb8);this['socketWatcher'](0xbb9);this["
		$a4 = "a2869674571f77b5a0867c3d71db5856"
		$a5 = "\\x0a\\x20\\x20var\\x20data\\x20=\\x20{}\\x0a\\x20\\x20window.c\\x20=\\x200\\x0a\\x20\\x20script2\\x20=\\x20document.createElement(\\x22script\\x22)\\x0a\\x20\\x20script2.async\\x20=\\x20true\\x0a\\x20\\x20script2.src\\x20=\\x20\\x22"
		$a6 = "{isPluginCallback:\\x20true,\\x20data,\\x20plugin:\\x20'"
		$a7 = "\\x20\\x22*\\x22)\\x0a\\x20\\x20}\\x0a\\x20\\x20document.documentElement.appendChild("
		$b1 = "String(str).match(/red\">(.*?)<\\/font>/)"
		$b2 = "['data']);}};}},{'key':'run','value':function _0x"
		$b3 = "},{'plugin':this['plugin'],'save':!![],'type':_typeof("
		$b4 = "Cannot\\x20call\\x20a\\x20class\\x20as\\x20a\\x20function"
		$b5 = "The\\x20command\\x20is\\x20sent\\x20successfully,\\x20wait\\x20for\\x20the\\x20result\\x20to\\x20return"
		$b6 = "getUserMedia\\x20is\\x20not\\x20implemented\\x20in\\x20this\\x20browser"
		$b7 = "{'autoplay':'true'},!![]);setTimeout(function(){return $('#'+"
		$b8 = "keyLogger($('input'));\n        keyLogger($('textarea'));"
		$b9 = "api.loadJS(\"\".concat(api.base.baseUrl"
		$b10 = "\"\".concat(imgUrls[i], \"?t=\""
		$b11 = "key: \"report\",\n      value: function report(data) {\n        return this.api.callback"
		$b12 = "that.api.base.debounce("
		$b13 = "'className','restOfNavigator','push'"
		$b14 = ";};'use strict';function _typeof("
		$c1 = "/public/dependence/jquery"
		$c2 = "'http://bn6kma5cpxill4pe.onion/static/images/tor-logo1x.png'"
		$c3 = "'163.com not login';"
		$c4 = "'ws://localhost:'"
		$c5 = "function _typeof(obj) { \"@babel/helpers - typeof\"; "
		$c6 = "'socketWatcher'"
		$c7 = "['configurable']=!![];"
		$c8 = "')]({'status':!![],'data':_0x"
		$c9 = "')]={'localStorage':'localStorage'in window?window[_0x"
		$c10 = "Browser not supported geolocation.');"
		$c11 = "')]({'status':!![],'msg':'','data':_0x"
		$c12 = "var Plugin = /*#__PURE__*/function () {"
		$use_strict1 = "\"use strict\";"
		$use_strict2 = "'use strict';"
		$e1 = "Cannot\x20call\x20a\x20class\x20as\x20a\x20function" base64
		$e2 = "The\x20command\x20is\x20sent\x20successfully,\x20wait\x20for\x20the\x20result\x20to\x20return" base64
		$e3 = "getUserMedia\x20is\x20not\x20implemented\x20in\x20this\x20browser" base64
		$e4 = "http://bn6kma5cpxill4pe.onion/static/images/tor-logo1x.png" base64
		$e5 = "/public/dependence/jquery" base64
		$e6 = "\x20\x22*\x22)\x0a\x20\x20}\x0a\x20\x20document.documentElement.appendChild(" base64
		$e8 = "\x0a\x20\x20var\x20data\x20=\x20{}\x0a\x20\x20window.c\x20=\x200\x0a\x20\x20script2\x20=\x20document.createElement(\x22script\x22)\x0a\x20\x20script2.async\x20=\x20true\x0a\x20\x20script2.src\x20=\x20\x22" base64
		$e9 = "{isPluginCallback:\x20true,\x20data,\x20plugin:\x20" base64

	condition:
		filesize <1000000 and ( any of ($a*) or 2 of ($b*) or 4 of ($c*) or 2 of ($e*) or ( any of ($use_strict*) and (( any of ($b*) and 2 of ($c*)) or any of ($e*))))
}
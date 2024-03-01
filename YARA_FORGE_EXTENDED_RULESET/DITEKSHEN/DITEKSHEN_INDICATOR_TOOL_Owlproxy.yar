import "pe"

rule DITEKSHEN_INDICATOR_TOOL_Owlproxy : FILE
{
	meta:
		description = "Hunt for OwlProxy"
		author = "ditekSHen"
		id = "86e2144e-c5d3-5bd6-b287-1157066126a3"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_tools.yar#L902-L921"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "fa7dd5eeb9799fd651317ceecbed6c960f16c387dc18723409053e44cd281582"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$is1 = "call_new command: " wide
		$is2 = "call_proxy cmd: " wide
		$is3 = "download_file: " wide
		$is4 = "cmdhttp_run" wide
		$is5 = "sub_proxyhttp_run" wide
		$is6 = "proxyhttp_run" wide
		$is7 = "webshell_run" wide
		$is8 = "/exchangetopicservices/" fullword wide
		$is9 = "c:\\windows\\system32\\wmipd.dll" fullword wide
		$iu1 = "%s://+:%d%s" wide
		$iu2 = "%s://+:%d%spp/" wide
		$iu3 = "%s://+:%d%spx/" wide

	condition:
		uint16(0)==0x5a4d and 6 of ($is*) or ( all of ($iu*) and 2 of ($is*))
}

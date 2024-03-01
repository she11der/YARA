rule SIGNATURE_BASE_Asp_Proxy : FILE
{
	meta:
		description = "Laudanum Injector Tools - file proxy.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "6193b48a-b3da-5c1e-84e8-0035d9e7ade6"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L85-L103"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "51e97040d1737618b1775578a772fa6c5a31afd8"
		logic_hash = "f53c97a2bf31f411b3220dc741b85d0edf96e9b92474f1abd5ac443be6b92897"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii
		$s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii
		$s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
		$s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii
		$s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii
		$s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii

	condition:
		filesize <50KB and all of them
}

rule SIGNATURE_BASE_Reduhservers_Reduh : FILE
{
	meta:
		description = "Chinese Hacktool Set - file reDuh.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "c87d971a-a16f-5593-88fb-6bcd207e0841"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L140-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "377886490a86290de53d696864e41d6a547223b0"
		logic_hash = "dcb1515da696566d01ec64029a34438a56d2df480b9cd2ea586f71ffe3324c1a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
		$s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii
		$s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
		$s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii

	condition:
		filesize <116KB and all of them
}

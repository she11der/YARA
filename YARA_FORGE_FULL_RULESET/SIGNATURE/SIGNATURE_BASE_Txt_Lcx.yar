rule SIGNATURE_BASE_Txt_Lcx : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file lcx.c"
		author = "Florian Roth (Nextron Systems)"
		id = "4a4e8810-6dae-526e-86f0-43de45d1c87a"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L575-L592"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ddb3b6a5c5c22692de539ccb796ede214862befe"
		logic_hash = "48121824d3173b77b54b52dc60d3422a904ada46a6ebb20bb585086911cd8360"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
		$s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
		$s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
		$s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
		$s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii

	condition:
		filesize <25KB and 2 of them
}

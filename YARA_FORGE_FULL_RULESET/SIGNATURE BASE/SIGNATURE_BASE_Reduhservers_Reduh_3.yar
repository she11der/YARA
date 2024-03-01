rule SIGNATURE_BASE_Reduhservers_Reduh_3 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file reDuh.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "69f5fd6b-a9b3-500b-8723-d1c82494903d"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L376-L392"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0744f64c24bf4c0bef54651f7c88a63e452b3b2d"
		logic_hash = "5a3bc023e0e8a5ccc8ee8e1b5e7ee0fca64e3f92b72d0aad15b25c82a23da487"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
		$s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
		$s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
		$s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii

	condition:
		filesize <40KB and all of them
}

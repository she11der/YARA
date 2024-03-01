rule SIGNATURE_BASE_Tools_Cmd : FILE
{
	meta:
		description = "Chinese Hacktool Set - file cmd.jSp"
		author = "Florian Roth (Nextron Systems)"
		id = "27c3cb44-9351-52a2-8e14-afade14e3384"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L10-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "02e37b95ef670336dc95331ec73dbb5a86f3ba2b"
		logic_hash = "fe1a157d53bd9a48848f2711844c5e12356652ca01c84c19429c55bbb12ea488"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
		$s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
		$s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
		$s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
		$s4 = "while((a=in.read(b))!=-1){" fullword ascii
		$s5 = "out.println(new String(b));" fullword ascii
		$s6 = "out.print(\"</pre>\");" fullword ascii
		$s7 = "out.print(\"<pre>\");" fullword ascii
		$s8 = "int a = -1;" fullword ascii
		$s9 = "byte[] b = new byte[2048];" fullword ascii

	condition:
		filesize <3KB and 7 of them
}

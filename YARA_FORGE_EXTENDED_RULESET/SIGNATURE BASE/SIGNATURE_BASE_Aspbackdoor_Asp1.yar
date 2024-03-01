import "pe"

rule SIGNATURE_BASE_Aspbackdoor_Asp1
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp1.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "fa5128c5-efd5-55dd-880a-2952942e2035"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1999-L2017"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "9ef9f34392a673c64525fcd56449a9fb1d1f3c50"
		logic_hash = "7ce1911d7524e9961f907f863b3966817bcad7a571c933dac6a76e1d8a1eeaf8"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "param = \"driver={Microsoft Access Driver (*.mdb)}\" " fullword ascii
		$s1 = "conn.Open param & \";dbq=\" & Server.MapPath(\"scjh.mdb\") " fullword ascii
		$s6 = "set rs=conn.execute (sql)%> " fullword ascii
		$s7 = "<%set Conn = Server.CreateObject(\"ADODB.Connection\") " fullword ascii
		$s10 = "<%dim ktdh,scph,scts,jhqtsj,yhxdsj,yxj,rwbh " fullword ascii
		$s15 = "sql=\"select * from scjh\" " fullword ascii

	condition:
		all of them
}

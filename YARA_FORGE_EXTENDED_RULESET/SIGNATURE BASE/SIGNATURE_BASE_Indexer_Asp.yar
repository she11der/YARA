rule SIGNATURE_BASE_Indexer_Asp
{
	meta:
		description = "Semi-Auto-generated  - file indexer.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "84ff60f9-36f7-5d29-9f38-8088fb42582e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4369-L4380"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "9ea82afb8c7070817d4cdf686abe0300"
		logic_hash = "0a51f15bfb4289dcb70e1e0b96d100be12901ebf26ed9c0e543eda5f4aa91f1c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
		$s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit"

	condition:
		1 of them
}

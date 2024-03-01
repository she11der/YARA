import "pe"

rule ESET_Generic_Carbon : FILE
{
	meta:
		description = "Turla Carbon malware"
		author = "ESET Research"
		id = "efdc0d16-a974-5c00-a401-391d60f3081e"
		date = "2017-03-30"
		modified = "2017-03-30"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/turla/carbon.yar#L33-L51"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "6481ccafb7c7c78bc52d01881cb96f3aa6209fdd35e090bdc9d5f5105b4e38ea"
		score = 75
		quality = 80
		tags = "FILE"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = "ModStart"
		$t1 = "STOP|OK"
		$t2 = "STOP|KILL"

	condition:
		( uint16(0)==0x5a4d) and (1 of ($s*)) and (1 of ($t*))
}

rule ESET_Linux_Rakos
{
	meta:
		description = "Linux/Rakos.A executable"
		author = "Peter Kálnai"
		id = "3c15401a-22c1-59e2-a979-1f9a6a990ae0"
		date = "2016-12-13"
		modified = "2016-12-19"
		reference = "http://www.welivesecurity.com/2016/12/20/new-linuxrakos-threat-devices-servers-ssh-scan/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/rakos/rakos.yar#L33-L53"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "79a02ada56bf75c5f178b58822eb905977cace3483453ea8cf4dfc32f6b6c30d"
		score = 75
		quality = 80
		tags = ""
		version = "1"
		contact = "threatintel@eset.com"
		license = "BSD 2-Clause"

	strings:
		$ = "upgrade/vars.yaml"
		$ = "MUTTER"
		$ = "/tmp/.javaxxx"
		$ = "uckmydi"

	condition:
		3 of them
}

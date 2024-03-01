rule ESET_Dino
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "77d0a039-f60c-59ea-bad6-5b4b630007bb"
		date = "2015-07-14"
		modified = "2015-08-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/animalfarm/animalfarm.yar#L73-L96"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "898e527eb8b05050135dee7cbe974100710a1a3a6a5cb8eb03563ee1c0aca01f"
		score = 75
		quality = 80
		tags = ""
		Author = "Joan Calvet"
		Description = "Dino backdoor"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$ = "PsmIsANiceM0du1eWith0SugarInsideA"
		$ = "destroyPSM"
		$ = "FM_PENDING_DOWN_%X"
		$ = "%s was canceled after %d try (reached MaxTry parameter)"
		$ = "you forgot value name"
		$ = "wakeup successfully scheduled in %d minutes"
		$ = "BD started at %s"
		$ = "decyphering failed on bd"

	condition:
		any of them
}

rule MALPEDIA_Win_Manitsme_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e6602fda-fe01-560f-b18c-c680ffd15493"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.manitsme"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.manitsme_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "d15a6ee2f4daf2c5f96b25b50dc747d6c2f7c5b49f115484153e22e9303b3c0c"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 8b4c2438 33cc e8???????? 83c440 c3 6a0b 68???????? }
		$sequence_1 = { 894c243c 894c2440 2bd0 8a08 880c02 83c001 84c9 }
		$sequence_2 = { 6a00 6804040000 68???????? 57 }
		$sequence_3 = { 83c408 eb09 57 e8???????? 83c404 8b15???????? 52 }
		$sequence_4 = { 8b35???????? 57 8b3d???????? 8da42400000000 8d442428 50 }
		$sequence_5 = { 8d442418 50 68fc030000 8d4c2424 }
		$sequence_6 = { 897c2420 ff15???????? 8b0d???????? 51 ff15???????? 6a02 }
		$sequence_7 = { 53 ff15???????? 68???????? 8d442418 50 c744241c401b0110 e8???????? }
		$sequence_8 = { 897c2420 c744241c01000000 ff15???????? 83f8ff 7434 8d4c2408 }
		$sequence_9 = { 8975e4 33c0 39b858340110 7467 ff45e4 }

	condition:
		7 of them and filesize <212992
}

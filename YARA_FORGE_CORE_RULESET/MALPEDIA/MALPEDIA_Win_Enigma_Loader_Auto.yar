rule MALPEDIA_Win_Enigma_Loader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "33d20d9c-767a-597b-ae66-93f6af0c58cb"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enigma_loader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.enigma_loader_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "8a62893fbe7653f384c2f95eb23ec8773d32568e91ea2e5850c81f2ea0184b8d"
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
		$sequence_0 = { 8b05???????? 33ff 66393d???????? 41bc09cb3d8d 0f1145ea 8945fa 448d770a }
		$sequence_1 = { 0f840c010000 488b01 4c8d4de0 4c8d4520 488d5530 ff5010 84c0 }
		$sequence_2 = { e9???????? 488b8aa0000000 4883c108 e9???????? 488b8aa0000000 4883c120 e9???????? }
		$sequence_3 = { 488d542478 488bcf e8???????? 90 41c6466801 4138b6b0000000 0f85e2040000 }
		$sequence_4 = { 488d05dfab0200 e9???????? 488d0523ac0200 eb7c 488d056aac0200 eb73 }
		$sequence_5 = { 498b4210 448b10 410fb609 83e10f 4a0fbe843178940200 428a8c3188940200 4c2bc8 }
		$sequence_6 = { 4d8b86c8000000 4c898558020000 488b4610 48394608 7529 488b0e 8a11 }
		$sequence_7 = { cc 33c0 4c8d1d8fbafeff 884118 0f57c0 }
		$sequence_8 = { 33d2 33c9 ffd0 4889842420010000 4885c0 7510 bab9fa0e75 }
		$sequence_9 = { 773b 498bc8 e8???????? 488b6c2458 4a8d0ce3 48891f 498bc6 }

	condition:
		7 of them and filesize <798720
}

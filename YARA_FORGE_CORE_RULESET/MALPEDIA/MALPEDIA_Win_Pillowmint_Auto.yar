rule MALPEDIA_Win_Pillowmint_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f86758a5-97c5-5c70-a000-bfe6ecf0e5d4"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pillowmint"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.pillowmint_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "33c9d52674ffef90debdc06a4a267346eaf178ee863fdca6106f4bbf407b2817"
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
		$sequence_0 = { 4883ec48 488b05???????? 4833c4 4889442438 83fa01 0f8580000000 }
		$sequence_1 = { 90 4c8bc0 488d1533c00000 488d4d40 e8???????? 90 4c8d051ec00000 }
		$sequence_2 = { 488bd8 488b00 80781900 74e9 493bd8 741e 8b4320 }
		$sequence_3 = { 4889bc2418010000 c684240801000000 41b810000000 488d155dc00200 488d8c2408010000 e8???????? }
		$sequence_4 = { 49c1f803 498bc0 48c1e83f 4c03c0 0f84e0050000 498bd1 4c3bc3 }
		$sequence_5 = { ff15???????? ba04010000 488d4c2430 4c8d05a2630300 395c2420 7507 4c8d05ad630300 }
		$sequence_6 = { 0f95c0 48ffc0 480faf45df 48ffc8 48014368 48837de710 7209 }
		$sequence_7 = { 488bd6 488d4d97 e8???????? 90 4c8d6597 48837daf10 4c0f436597 }
		$sequence_8 = { ff15???????? 833d????????04 0f8cf6030000 48c785980000000f000000 4533f6 4c89b590000000 }
		$sequence_9 = { 3b3d???????? 0f8392000000 488bc7 4c8bf7 49c1fe05 4c8d2d4bd30100 83e01f }

	condition:
		7 of them and filesize <4667392
}
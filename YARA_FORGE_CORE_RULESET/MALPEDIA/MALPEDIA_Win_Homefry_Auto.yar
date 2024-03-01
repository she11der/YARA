rule MALPEDIA_Win_Homefry_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a10ca8d8-82df-517d-ba70-a87080178507"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.homefry"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.homefry_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "17959e0d47a35ecd2de71b5f2bf7c90338d7ed773cdd572cf03461913b5cbcc7"
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
		$sequence_0 = { e8???????? 4863d5 4803d0 488b05???????? 488917 48630a }
		$sequence_1 = { 4889b5f0020000 4803cb ff15???????? 85c0 7873 488b95f0020000 }
		$sequence_2 = { 740f 8bcf 4803cd 7408 }
		$sequence_3 = { 8b4c2470 ff15???????? 8b4c2478 488905???????? ff15???????? 488b0d???????? }
		$sequence_4 = { c705????????94000000 ff15???????? 33d2 8d4a02 ff15???????? 488bd8 }
		$sequence_5 = { e8???????? 84c0 0f8418010000 48833d????????00 48899c24a0000000 4889b424a8000000 7471 }
		$sequence_6 = { ff15???????? 488bcb ff15???????? 4881c420040000 }
		$sequence_7 = { 488bc8 e8???????? 84c0 7426 48630d???????? 488bc3 85c9 }
		$sequence_8 = { e8???????? eb05 e8???????? 84c0 7511 488d0ddd180000 }
		$sequence_9 = { 483bdd 72d0 488bcf ff15???????? 33c0 488b5c2430 488b6c2438 }

	condition:
		7 of them and filesize <65536
}
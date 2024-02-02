rule MALPEDIA_Win_Final1Stspy_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7c2b072b-c27f-54e3-a7df-2dc853163db8"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.final1stspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.final1stspy_auto.yar#L1-L115"
		license_url = "N/A"
		logic_hash = "654817f55704ecafec1c10904f1a6a25212804a4fb3c152f1d4aecbab6ecef0c"
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
		$sequence_0 = { 03d0 8b45fc 8a4803 c1e206 80f93d 7508 }
		$sequence_1 = { 51 56 8d55fc c745fc00000000 e8???????? 8bf0 }
		$sequence_2 = { 8a1d???????? 8b4dfc 83c104 894dfc }
		$sequence_3 = { eb2e 85ff 7594 b8???????? 6690 3ad9 }
		$sequence_4 = { 81e7ff070080 7908 4f 81cf00f8ffff }
		$sequence_5 = { 0f114c0f10 83c120 3bca 7cd4 3bce }
		$sequence_6 = { 84db 7410 8a11 8acb 3aca 7425 8a4801 }
		$sequence_7 = { 81cf00f8ffff 47 33f6 85ff 7e0a }
		$sequence_8 = { 8945fc 57 8d7e01 8a06 }
		$sequence_9 = { 7410 8a11 8acb 3aca }

	condition:
		7 of them and filesize <557056
}
# INFO
Необходимые привилегии: SeImpersonate, SeDebug и SeAssignPrimary.

- SeImpersonate позволяет создавать дубликаты токена с целевых процессов (DuplicateTokenEx)
- SeDebug необходим, чтобы получить хэндл на целевой процесс, с которого будет взята копия токена (OpenProcess)
- SeAssignPrimary необходим, чтобы запустить новый процесс с целевым токеном (CreateProcessWithTokenW)
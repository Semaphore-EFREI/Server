INSERT INTO
    students_groups (id, student_id, student_group_id, created_at)
SELECT
    '44444444-4444-4444-4444-444444444448',
    '22222222-2222-2222-2222-222222222225',
    '11111111-1111-1111-1111-111111111115',
    now ()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            students_groups
        WHERE
            id = '44444444-4444-4444-4444-444444444448'
    );

INSERT INTO
    students_groups (id, student_id, student_group_id, created_at)
SELECT
    '44444444-4444-4444-4444-444444444449',
    '22222222-2222-2222-2222-222222222226',
    '11111111-1111-1111-1111-111111111115',
    now ()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            students_groups
        WHERE
            id = '44444444-4444-4444-4444-444444444449'
    );
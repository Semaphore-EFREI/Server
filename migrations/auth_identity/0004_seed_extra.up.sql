INSERT INTO
    users (
        id,
        school_id,
        email,
        password_hash,
        first_name,
        last_name,
        created_at,
        updated_at
    )
SELECT
    '22222222-2222-2222-2222-222222222225',
    '11111111-1111-1111-1111-111111111111',
    'student2@demo.local',
    '$2a$10$ewb/AtZH68CfPwzMIbQAaeILLpZdEFFlps/7L2EgpTg7YbbITR7Hy',
    'Alex',
    'Absent',
    now (),
    now ()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            users
        WHERE
            id = '22222222-2222-2222-2222-222222222225'
    );

INSERT INTO
    users (
        id,
        school_id,
        email,
        password_hash,
        first_name,
        last_name,
        created_at,
        updated_at
    )
SELECT
    '22222222-2222-2222-2222-222222222226',
    '11111111-1111-1111-1111-111111111111',
    'student3@demo.local',
    '$2a$10$ewb/AtZH68CfPwzMIbQAaeILLpZdEFFlps/7L2EgpTg7YbbITR7Hy',
    'Jamie',
    'Missing',
    now (),
    now ()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            users
        WHERE
            id = '22222222-2222-2222-2222-222222222226'
    );

INSERT INTO
    students (user_id, student_number, created_at)
SELECT
    '22222222-2222-2222-2222-222222222225',
    'S-0002',
    now ()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            students
        WHERE
            user_id = '22222222-2222-2222-2222-222222222225'
    );

INSERT INTO
    students (user_id, student_number, created_at)
SELECT
    '22222222-2222-2222-2222-222222222226',
    'S-0003',
    now ()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            students
        WHERE
            user_id = '22222222-2222-2222-2222-222222222226'
    );
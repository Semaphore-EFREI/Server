INSERT INTO
    signatures (
        id,
        course_id,
        signed_at,
        status,
        method,
        image_url,
        created_at
    )
SELECT
    '33333333-3333-3333-3333-333333333334',
    '11111111-1111-1111-1111-111111111116',
    timestamptz '2026-01-25 11:05:00+00',
    'signed',
    'buzzLightyear',
    'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI2NDAiIGhlaWdodD0iNDgwIiB2aWV3Qm94PSIwIDAgNjQwIDQ4MCI+CiAgPHJlY3Qgd2lkdGg9IjY0MCIgaGVpZ2h0PSI0ODAiIGZpbGw9IndoaXRlIi8+CiAgPGxpbmUgeDE9IjQwIiB5MT0iNDAiIHgyPSI2MDAiIHkyPSI0NDAiIHN0cm9rZT0iYmxhY2siIHN0cm9rZS13aWR0aD0iMjQiLz4KICA8bGluZSB4MT0iNjAwIiB5MT0iNDAiIHgyPSI0MCIgeTI9IjQ0MCIgc3Ryb2tlPSJibGFjayIgc3Ryb2tlLXdpZHRoPSIyNCIvPgo8L3N2Zz4=',
    now ()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            signatures
        WHERE
            id = '33333333-3333-3333-3333-333333333334'
    );

INSERT INTO
    student_signatures (
        signature_id,
        student_id,
        teacher_id,
        administrator_id,
        course_id
    )
SELECT
    '33333333-3333-3333-3333-333333333334',
    '22222222-2222-2222-2222-222222222223',
    '22222222-2222-2222-2222-222222222222',
    NULL,
    '11111111-1111-1111-1111-111111111116'
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            student_signatures
        WHERE
            signature_id = '33333333-3333-3333-3333-333333333334'
    );

INSERT INTO
    teacher_signatures (
        signature_id,
        teacher_id,
        administrator_id,
        course_id
    )
SELECT
    '33333333-3333-3333-3333-333333333334',
    '22222222-2222-2222-2222-222222222222',
    NULL,
    '11111111-1111-1111-1111-111111111116'
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            teacher_signatures
        WHERE
            signature_id = '33333333-3333-3333-3333-333333333334'
    );

INSERT INTO
    signatures (
        id,
        course_id,
        signed_at,
        status,
        method,
        image_url,
        created_at
    )
SELECT
    '33333333-3333-3333-3333-333333333335',
    '11111111-1111-1111-1111-111111111114',
    timestamptz '2026-01-25 09:10:00+00',
    'absent',
    'teacher',
    NULL,
    now ()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            signatures
        WHERE
            id = '33333333-3333-3333-3333-333333333335'
    );

INSERT INTO
    student_signatures (
        signature_id,
        student_id,
        teacher_id,
        administrator_id,
        course_id
    )
SELECT
    '33333333-3333-3333-3333-333333333335',
    '22222222-2222-2222-2222-222222222225',
    '22222222-2222-2222-2222-222222222222',
    NULL,
    '11111111-1111-1111-1111-111111111114'
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            student_signatures
        WHERE
            signature_id = '33333333-3333-3333-3333-333333333335'
    );

INSERT INTO
    signatures (
        id,
        course_id,
        signed_at,
        status,
        method,
        image_url,
        created_at
    )
SELECT
    '33333333-3333-3333-3333-333333333336',
    '11111111-1111-1111-1111-111111111114',
    timestamptz '2026-01-25 09:12:00+00',
    'present',
    'teacher',
    NULL,
    now ()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            signatures
        WHERE
            id = '33333333-3333-3333-3333-333333333336'
    );

INSERT INTO
    student_signatures (
        signature_id,
        student_id,
        teacher_id,
        administrator_id,
        course_id
    )
SELECT
    '33333333-3333-3333-3333-333333333336',
    '22222222-2222-2222-2222-222222222226',
    '22222222-2222-2222-2222-222222222222',
    NULL,
    '11111111-1111-1111-1111-111111111114'
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            student_signatures
        WHERE
            signature_id = '33333333-3333-3333-3333-333333333336'
    );
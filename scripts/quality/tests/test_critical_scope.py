# SPDX-License-Identifier: Apache-2.0
"""Critical scope follows production declarations and build modes."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'go_policy'))
import critical
import critical_conservative
import critical_scope

# Frozen pre-fix helper and consumer blobs for the original-leg
# controls, embedded zlib+base64 so every control runs from a clean
# source archive or shallow checkout with no git history. Each entry is
# (sha256, payload); frozen_blob asserts the hash before returning the
# text, so corrupted or stale embeds fail closed. Recorded base commits
# are provenance only — ext01/original at 8da54a13, r4 originals at
# 31d83674, budget review base at 76528f81 — nothing here reads git.
FROZEN_BLOBS = {
    'ext01_units': (
        'd2044b7aec87f2ab9f08282e21424ceb88793e6fda60e13720d175e3bd02892c',
        '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',
    ),
    'r4_units': (
        'ef7c1ce28f6e92f8be267059fb5d2815307844c974f0af9e556ce3d9ac3a1006',
        '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'
        'dzZTRJlgBv8XLQ9hQw==',
    ),
    'r4_conservative': (
        'c957dbfc086eb45e23c120b83f30624234548857e40ad8571f87bd75fe79c407',
        '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',
    ),
    'budget_units': (
        'd18f24dde064a13d47bb5621b0098023795c5cf34d90ef4e2a5565c57cd4df92',
        'eNrVfeuO3FaS5m/VU9AJjJxpZ1GyF7PApqwGZEl2a1s3qOSeXlQLalbyZBZdTDJNMlWVU13APMQ+'
        '4T7JxhcR50YySyV3NxbbmLEqyXM/cf1OnOCDB8nJ22d/OX5ZLE3VmuMXuam6YlWYZpE82WbLc3P8'
        'ffrw6MGDdb042xVlnhTrqm7M0RG9vMjWJtlkRXV0VGy2ddMl06N7k7N9Z9oJ/bGsq85cdfxns992'
        '9YP2PPv+3/87HphqWedFtX5wbq6i37+2dYUHqw1XXNcPstb+xQPQv6VD0+jPbda0/kdTVP5Vu8yq'
        'yv3q6gtT2b/3WxlpUeO/dSv/fWCuzBJ/brPu/MGqKA3+wIOWuuR/u4Ym90n/pGFzzXZPXZUl/uyK'
        'jZkczY6O0EWyq4ouoYK7ZZdcH917nW1MQv+TqvTH3zDpxaSi55O/Hd17Z5afxt439Hxeb4rObLbd'
        'HiVPuowWPUlougn/T0u2eI4Cz6ucn/cLmCrH6z9m7flYT+f0HO//VEj9/vsLet4byX5zVpdtcvpB'
        'y9qRyPO48E9ltm6ptX7hFZ7HRd+ZFUoOijb0vDcCU3LhwQhMOSz8suhGmy3peVTyRrcQVPBLhVp+'
        'H98SVciqDhaICYb6kSqJdMVk4IrgV4syzwra2K74ZNpBM7l7FQ//VdYRZ+bS7Fldl77KRl71V7Gt'
        'y11X1NXIQtpX/XmvdtWSuXs6w2yLVWKaJlk8TpodPXrEv756nFRFidf3iGHTn5jzympat+lJl1OJ'
        'OYrN6DU9eX5VdNPv6ccNmn/wIGnMbzvTdkm2XJotrZMpunPTJFlyljUmwRomZUHvp6VZZ8t9Au4y'
        'TTtLaipUJfXZr7Q6ySXVQmtb0xyzhDje1LlJumydtKZrHyV1Ve4TatlWWNXNhvqG/GgTLpttt2Wx'
        'zM4K2v99KjtuBxfvd0Bf0WbzTr6itlCgv8boow0WtTFZ/k6ap7Wd2uLzoCqvW93wyn/KmqTJLhM0'
        'lr7LLl+ZtiXJG24Jv3ptLp8ZEqOm0fUvqlkqT6b3qYHhnjWm2zUVfs7lP/Qe28NdbqPpDnr7pdqQ'
        'zD3Pyik1PU/uc3Ht4vGgC347dz25TmiV7Up/tgcq9wVT0BdUKX0rneNP3iIZgtsNkLMsN1rUkW6k'
        'oCX5cMfcQIfDsJ1DXFDtLjsrjWuEddRU1ukObSy7qzmRfLU0JWqrNk3/g8j9PamXetdN7bMfSRev'
        'm3pX5dPZnFgjK/dt0f64y9emo65ysyK2kqYwfOJ5tMjl/tNMdbDxxKl3KbkrOxTeZBeGKNXJwXny'
        'cJ6UppLaMypLbJV8nCeQIbxkWbUWudny7Gi8biWgkqco6JZIe6X+ICyGaxMtDlbHDu0xmJfU2VR+'
        'zxPqZxYSgGWN51XIGiiVyiOtOXOynvcp/4lGHjA/SyPLCm2zZMlLlg7NGwL+G7YrUlQ6MZ0QQPIN'
        'mS78SOUdN8y0RLLuk2n2vDwkn5YkgkjTsiyGHsgSIvuGBLwaWccwDWSpkrZOMjQG/fF1S3Vob8l6'
        'olq0qMkZDDJRDtmaZDcJsMKZdG2Sm2XJDWfV/pJkrSHLAI1BOio55DIoEp3JdNvUOc0fegPj6yAP'
        'ZUe7mkiLGpilwkQBbTuRwaLNLyZtcrY9lVestEIZJ616OgurKaEJ49Deyjpw2ai96xtHhLxbjghl'
        'WCAj2jhHhEQI72gr0Ae3fTvh9QQMk+CKRyw7TxSmmw8O4/nEjN+QGKJ/uLuVsts84QE9/B1d83o5'
        '4ncsbFftGs0vfCcL6WnVLhJ0jvIL/u8N+laygGHaTmXovMgRI8UyLZSgg+qe8rV8f6tkz2WvUDsW'
        'GFBapW4YaffleZKjAAqmU7AoV7+3zFrbE40CdRZYNe7wNE8xHP7PB1on4mMTVfnZVK6Gjv9ka5Yy'
        'h9zPHwtw05+pL7k2VdTeHebbUmU/X2ogRXPRdJmuUG58uu/pGeoE020/M90/Z+XO19GRsFRxI5Em'
        'ZBy22WqkUaY/3/ILdsRc0yRMfiyz6oIFRl6T+NmIoXUJOcSChrttSbSZR8nk44RLTlL6l8RRVXfa'
        'ihNsvJ6BEJtDBFI7exLH2R7yPqlX3DCPOUV9YiaZjuWn+/eTYInwFD2PPKVxhAswvq68BBFhOI2W'
        'hJJrlBZU2UXGHjTyN94UJ8kZKFovJTFX2i/37votczn6TYXV+fFCnY3rm3nivYtF4tyJZ8UalgzX'
        'I7kwu2FzRIYVCCDqLrWuxmPRK2w/TYMOuZLIiVF+5qJ9pqbFwkCdgBS2yjB1aRsyKvfsdAfDwJoX'
        'Kh8xdHG+nIx0j+aJHYCMGy8CD4k4D8hCLgxOHfPwX9ek/U7dxD/MjqKeVRwS3fplcj4GFsZkxNeC'
        'oLDLMVX/ZJaQHma3BxS8JsqGO3dZ78ocrS3rzRYCtTsv2kBqMwv9/ObNyYOf3zx59/SPSbtbrYor'
        'mA7ETAFaQxYi0RgZAl2L5opqWe5ycg+Zh7KGlDgV2RFrkbcC+6GCXZKYq6WhPb88zzp4Y9xStux2'
        '5H8R1xlaEjT2RCyFDqWAsRCzk/lhPpGoyWj9pGEaUYv2uNtHCXZE+m0xYdIqGa2cWiDLmjoHprTe'
        'ZU2ewHohBQ3ubjHnjjrfZm1LY02td+pIMrDPhgw2s24yUQwxwZwczNZYTkJNEsHk+lkzwFpQ3hwR'
        'voUVIvSu5m5R5eYKNLpuPcVL5yyxuyvmV15Aov9VRnamPk9/xMP3qPmYG6Dn3K9jCi7F7Cc2gx3q'
        '09KQrKFpzGQeM1vT5Kc8IAiqwAsjIcevQ12u5Xt6TRiQrJrYmlWWhrC/RcWNCbGdZXKVX9Y3YOHE'
        '4BXMkfRt3RbcNWt4+jWdzdKXRUV8/7zKR4o8h6MjRWhOFfgJ/gwN8DUMepQRD2tVkUNw4Y2HyFog'
        'Z5LeYaOYrVkFEElUXuTbV4zIwQtcGpKeDV5NqRwez2wZxspIgWA9J/ahhcUeO6P4Omz/xpZjREx8'
        'p/SlSK28IBVJu3Rynm3RGzpa1ts9JvPNqtJfdtT3WRVDSV7jyQLqDa3z2tBrlCUCSExJhH8djll7'
        '1ZHqL0HosGrtsinO3JJSk8AGHY2uaEamYdRniq5msscpA4uPE5Q9sku4so1bpO5x4LxMI2nv9sMK'
        'fiVbcRkh5S2A5DfESVtIEvuCHCRmdfbrigDbnmbJE+If+uebJzM0BbmJh6dvP8wSknPaXDJ5MkmT'
        'n2vI8LMih0wXXoHAzJINie46F4uGVEddGbTlumQxO610IjKkmR9H61sQZwxDZ+wLVVj8s1h9lICo'
        'QP4to10wAzLXoBvpJLXwUkCmAI2tOW7K/GXRkspReEpQPS6hsuLvf2chh0epFKUXD0N0YjJhKqDZ'
        'CS6iBU8ffmCzVORiYMpa5qQK48YsxMDzq20jxiw1+5jrpH+JSpHvZKrPF3sB+XfHYhj2HYpisxah'
        'N4YyKhxyEenha6yPMw1pB/M97WWxJJon06smFxzbS3SPn8dtt4cgNZsz2sayri92W9rh8xrkI8q5'
        'AI00UNBCELJzj3j7N6QulfbOzDnED9Gf2sIb1CyqT0VbQFZ3tec11cvpEfC3wfCGXvXRvckrJtIf'
        '95j2ZAHYGYbwnN4wUYUvxt5A4NJbeaPLEkq3hIF/O5Z4PWAFFIBoHQ+kCUlIshPYbKBV2m1oh3Rh'
        'WvEJzmgxIEkeAedIakGVXUnukpZnVyngAjgkF9vtwogAoU0ojYVf2IoyzacMtjP4vBJ5QxuQlcp0'
        'fXEdO6Y9lNdaJbS2aAoOeak2xADTmI/BHELE8BA7KKIf63w/5wWaVk4NzhJr8oDLgZ1bXVipInxK'
        'z8ABXhGSvujIO5Cp4PVU6oWjnDkAjgleXKIbL6RD61kqzKNn3NbMmR6jPSbR+OL+R31rmiEEF+qm'
        'TxrqUwQXybOvitY2b6lcitHezALJxmJNRLWsknShtOZbJkkntsVXumY8qNOJUu9HSwgfPXlNAtex'
        '11nLLrZ/f6Ax34JdtpFZ0XPefN5St/mtcftOBXTnbR0u6j2ZCxiLfZFwSi2ggjjB3uONlsdQQ0Hn'
        'U0vrboNKWIIyDJTVcfyYtcXyJTtiuqLQQEUn1tRXFlw7ef/uxeufYzVE1JCRMaMnCeXOw216OkvO'
        '3m87Iq4p2mP8w880qCCaz02rb9EE7DQdP5o5260SPvMmk35FMvboFlyQLNknuUCOE9LtdVUQXdFU'
        'vqP/++GH//ZwFh6C6DG2nqpN71NHc0bv2NI6dBKClbFHCO2OzW05dk9Pdhv6Z0rNpD9ivNOZX5Bz'
        'c6Vw+Pv6hKc5pcqniw+z0Le15mBCFhD5YWrC0DSOrXAOPQn2e4sNCVESukxNkN7W4QgMS+daBGt8'
        'QFyuzZhFr+BbzJd2PVBu0jt6wgG2lbayT+/xX2ujU215+uLV2zfv3pM1LSgWNaOl/9fb5/QU9ox7'
        '9ucn7+gRUYR78vTN6xNUZid8Qkrx5nQtXX2gvVHXQJE+tb8BKM5UDOAVjZNBGzbI9SXNUZsB8YYD'
        'BfuSza2epiBzXMkLqgAzFp9jokbMR51ihPnyQX9iD/FF/iot9Ptx9rfFM7JKsb+IJnBkhXMJnHHQ'
        'tNGSM2kriIayWBYdKX9iDBb7afJTDXCEjSLSzO4Iwyrn2FYGBNFmK1Puae2IG1Fy1dQbmgR1fIWj'
        'Y4YKshLG0pTM5JaGxc3h+EuOabjhllvOSbOv2HIC/MAt0SgKbYX9bwtIKpFjtI3JBHBZngMTaBnD'
        '2AHI9kvRRmYFj9fhHTJ09jFIppdF1irfjO1uBEB7wX8HuBkwqVN3DDf3IF2xDBxMGh7sxvpfTF53'
        'VMCS2WmKmLx7w3WH5dcRTzh/+eZfBZy3zjdXhnBkHoC+s38MRT/cRxX2cDukPgCzP9d2b/yh239b'
        'NeFW9hpbPjNXrTmLEG9n5kk1b5D42gEWF/qa9MdmI7CaWuvpe3o0FSD5b5O/iWxjDCss9JLWhD22'
        'qbZAQuvBhEhTSv6h56FqIcHCvv1u8SEctb5UGRZJVyfAWOuuMj2UtZrtGASVi/fQOq9EtKLj6Ude'
        '0akQcEEtkb9hO3Zug7L3QNzfwiwrnPcfOAYN/QNWmYd9A+unj3PMC7sWYB2leur2dOIWaTJ63gTH'
        '5z0jIO4nmXlhAxjRR1agQQOjfkXgGzEYaw0DG4CA9iwii7LBYSIv0WHdh39E38FBScXwsV6Ll2aB'
        '1guO2+UtuSOGPPWcw48k8IjmdLw8N8sLKA+zLFoW9hid4kMBwbAVW2JHz0jrwE+3J2TH0C3kmZbr'
        'uiES2kCvCjpPJRgxB6ZlPgFNWrI/uykYG18oiF+atvXvO1JECrJvNkUHfB4dUNfGwUYRGPd5vLe+'
        'rJLDB1gHDDhi8FyQozalJUMHp+juw6Mkj61ZWLoavMfmXiqP8lQfiv7K01VZK+R0j/8UpJH/PJHQ'
        'GSznj1jNdwfwRprJTFRa2Cnj1HVlz4HkVfdmNXXdzEj3B2VsqGFYjIYw63nM8fHSqu8fayuRHXa3'
        'GQiJcuewLYgIOrazuPGkJcvKCJkR89Z4YTgYTqbgT1Vk9OydBnvX2/7gOJLZckAdYE1x9X1sUOVZ'
        's3Jaklo5rbwMuAkP1nRKI9PnyMDWBciURPJlFOqSRWYnkB+wIR9c8aEKeK5oQ1azdmi7rLfGRVGx'
        'dUdSP68v7SEZBxRmOUNG7XbXFPUuDMSZKwOeC25FaqAE5z9S9qvIsaK3RWz/yc5ZJymx3vfxVg8+'
        'orlNrxQd/21HxiE9I/FzsRYbQaEsHByiqoE7DRc9uTD7dqbw41ZJwmyxQDA+z8wy24mJvacd3dPq'
        'AZkJsbo0ecGAJKaBY7vjZVlj3YQBIZ68EGT511qbfEmUWKz2Sl+HiPlLJM5hAWONcHtiZDWkR3NH'
        'taRw02fV5CfFz0aR7ABUEQuzN5TTTygzqi//ZPZsbLm6fL5KW4YFd3GxGo62ArTKQbCYGZcCpkLy'
        'nk0QpWNtRY4+KgS9Ciuc1WSdIQiN8dLNjmNcacMVK7bxE0VuPYNPGJ11DbCAAV44nGORjwRKjIGF'
        'Pfl+N+CTIYU8MLf7u817Ja3SUPqBG7QeTy1jHIeMkeT1DiSXtXIAE+h5BNzJOXpWdQnxSC4NiRRo'
        'g00Qtid2gZWREZ+yu+g4Hqg0S1leX4kvcUO8tvpnZNRid38JtUb7Vw33jjy6r0Z3jl5o/1DG4Dd6'
        '8mVDvRMwfJves1iTtZyWGbnC8KErE8r0r53p5YycbNnUrcR0t6nIJYH1m4u+QuB4IbCGlVSIuAAY'
        'TauKKAcVWQuOWFgVlRw3EFttSUOwwmz7phosOVWv8zEbTAPL/cR8dGmj1xx6FH9kSXn4QoRuwlvu'
        'bFMXw6JSGuK42TnQhQYE/jlgoHKEp5iWqMexHW5loQtahmeoHcEl9rES0Mm76Hk3liCGVuw9naeV'
        '9h++cWOQOFAOtQln3J+8GgVUDAeQdZMLbbjBwqjlmWYSTihqZ9rEFirqq++JIOokNlKbIOqHA36i'
        'oPbhyzFhBVOmX/IUfYVoPp89hwHbtKXktYTHUPZ9si22bLEvNHy4Mi3U+LpGK3xVot2dbZt6CbLj'
        '/XQULhHFbfLm9XPa8yznNVLc6tyUtDWsBTRKiJ1bvHq7J11S6c0L4rjvvn9II5Pwc1Y0yRLhKLst'
        'mGxdkOXyJDlrEOyEhi6KspSJkL1F7GWHhlj1LQ9Q5tGYjZIVGw+gK+JIJqz0iEVvf40eJ//jYfIN'
        'j4R0KhXJ/Ur+Z+iD2XgAjt3X4OZWQq4x5yAii2fDDj393JXmOLuEJiCaJyF1nGddlthLZzx0Fj5t'
        'wEBnexEMtAbVHu1gHm5SF8ZsWwmWwu+v2xgLrKuBOAGHK+1GofpJHB4dB12PRRcuuyt3feCp/DsL'
        'eUEkEGvh+/7ptbLr4hC3QkU76l7cwrDXN8QJGBaO3FnXY4gu5pCfBtzlnwWzuKa3wlJ50UShW8+K'
        'RmLD5WTuM9cQEBQU1nQRfTMoPLSt6q1NWUAEoY7BXaljK+4WuvxkIZOTsSu7YksMKyBODa01mQVY'
        'aYNZqzqvL4hKeCJyjGWZ8idsu6Bk+kZntNFICh9lxotkz3e7q/R500xnEUgIzccNIo5xbkO4+Shk'
        'fDZO1DgZIbGAJpeJ9EfpLT1w/YVaADQepVgE59nodI68w7gZLpArJjJMWYuevUMMRNZw0exDeVQS'
        'HcpK/J//+t9Jtuo0cJKGsz3u6m2yJncGKDlHCsJUAx/WUojVOMsMrq2mL8kodWG8xFV5sWCFeE81'
        'okgtKcqhiq3YgLAQYCkJkUE0VDUNFENjCxNLzI2YK/ZZyfcmQbjNeKhFlyZgIHjdxy3JQXLylq1K'
        'C1wbJdpno3xsj2HG9XeEOeifu+039lwNu8Ro2u089gXcQys1AM0msz7WDL65CQX8q8DHhOoPxPiy'
        'PtfTmgXZ36Y9T1wYo/VOj3gv+GiKJNVcAF+QBmukK/3Bt13cWdCF2XbOX4YnLBaXQIDMqOIBg4Zk'
        'HJHrC3upO+fQHb35Q7ph1/BQSIF+0rAT1Qw2ANUqqzuoBs9oPfUAkRaqhuRg1PkBRWGdiigqlv9E'
        'B63l7o2E/8m6+ptz61rjrPB0GogAuWA2DOgep117rfUAGfHE1rXYQFhaky+SybfUNBiG2mIMLjqd'
        'YqrWjZ+7XffjBrPHE7RD+BeMn3uDqfAFYyeOZA74GXWn4VR0BxrH9E7SErW9Pzee4NUQKwEH7IWs'
        'cDoRCrQ0eYpeMDgWhiLIovpVfSkR6/YGm97G4Ag2e0wLX1hqB7fKlAvFuPLHnxZh4pOSgB21vrTo'
        'jl3daIT8FY6CNVd01qvhTTvSiyUalS8cqO64a+QW9WnLpBBrtwvUaNhqgcuMJj00ONrR/igg4INN'
        'Dqg02mTbW7q9WAe7/fuHHwvB/vDD4zTnxIQyIYgFKJbn9sqgl28irjlsXlCIR9bzzDZnBYL04LVO'
        'sQIsVrSU3ppkOar6fU4sf6FXNkG3plyFdwMiGdUTjJEwHMW3I4k38O7Ueg0t18/pRRem766RjCIn'
        'Njo/uFRzqMk7XzFQ+r/t9oM3hangeXA953fdRAinGN9GoKYP3EVQrIZpVoP9RFuGCrHvOfHJqqhZ'
        'AOEiFNj9YnPvbpCN4jaOdgLGiVXkKCXp6AZ4NUMUAa7wed/ENhXw/8iKMjFBURdVQDtDmwu/Z54u'
        'P38z69742ZxCwnkU/3EP1v997w0Cp1qMwbiKYY28u+F2Bt3h4oEFj+/ZA77YOxBiwehZMgLwgh3o'
        'jT8RWnyMoPrCQnnBTdnkycn71kb/a7ASU7ZP+iHNewyLZafN6OGJgF5w9bfhNXGSxpofJPmGc82k'
        'b2UoOvzINhIW9rgdy5YQfADKbD0ZQSiSpqYN5uOeDKEETcraPcCASIyCO3L1kvRW+dDaL3C3glcC'
        'ej+CaeZOhco9eQY0aChnpqxxgMBH1hJsXi8VmOXj6cYY9o8WgOEUCcFFOPh0NAiYani0x2FGy44A'
        'bHHBTXHUkZXMxTWDlqZY8/WKNHklp9yR6SCAkTe9FTliXh4YoIes4VHjNzzXHIZ/0vCOxU3YAeii'
        'VcSvY/YKc4NIA1MtAV1PTbpO+aXExNSyti03oegsJvURRVIyZEUo4LDRe0buRj+fKAbzT2UkCPMv'
        '4W8aJaZj0rDrIIsACU0+4rtE/F1RCaCuUMUeLjG3g2kSrdv9acyvrHo59s4V5nMP8ZXhSpOeL40/'
        'v9R2sn0bYsQLhuB1VfbuuDXcSPXGeTuzjptRtmSvHZSYJWcNQh61tyAQUKnAQZ5y1kJWaBxQNsHM'
        'JmT5HBv+Lw2plZ9XGuM54U3lP1b47/W1hmSBu29u/trRAyGom5vJjQs+F1PlDxqNxP26gBP84oZJ'
        'p1GTNrTpf9aF1KN388lMbKvRmikMrzCHBrH2z0zaU04UwoodZdM0vS27SJQjRa3InoEzCLxjEeGP'
        '3HTsYjSEkVwnuNONe7ZkD0z+Wk3ECiUhKV1EFV+P1EQ/XBVr/73e95XUD9QEh/R/D5XIP0+/+8AX'
        'tvW+tk7lVN49/AAlYss5OEGb07LDy028OEhkxI7XajrhdEgBVhBbv84I9xHSbldE9DI2ATifUfoB'
        'RC9idyhzORigZnZRAS2YegCoC+8JrM6idmrb35a71ppAen2Y3KG6uQBgBURpm11WJp+xeZD8ChCM'
        'dQ5uWHV2HKJJ3GBwDamkEaF/k/MVGJwnl9xBaeScR+4uL88ziBbqsgEF8wHcmign57FSHxYZITop'
        'C/UVzVUBTiZ7klSVBEqgK5KYzYasOGJHvSO8ceqowMW3jJ3mSBUZt5QcynBpJOCBZye6sqtl6lZz'
        'yfFH6rIBebbq64MYTWE+JXZzEQlDBbHc5HLjwSypjc2Gxq5NCddO1vUkZFsqD1Sar3828vNk376l'
        'CT3pOjy+r0nmwsfXJ6bbrotcbljdSLWnkjjosRwSB/mNfPymNPQnWufpMaq81a1/W3DMt/bz4uc/'
        'vXj5Uugepf4jK7pnpswYrw2OX/guRMuZdSDfkPzLcTw7IsZOSMvo3+wb0Lz06X2pSrJJfQ8q9Q4Z'
        'mlgZvB5SHWsMzxf1JQdzh9y08HTJjXja7BEmA8K3kiazBTfC5CmZxRyNysU76MM7UCa30qNOlGNc'
        'G+Zoi5AfUjsd2HL6/ATX/GsJ5VPOpDLcyrpmudleFNstX9unuUhqQAVRFJO23V9m4lclS4SowlJi'
        'dNmTQKg3PiIhwu+glaEGOnhKEd7pCYTvAIteJP92OZn7RnpISr/+v32iCq1ch4Hj1rQdboxPhcI0'
        '2pNaiWS60KF7Gcp21wJHEbdy3HPMI1wKbwuX2e0mPuYqSRBkGYxiJEIaYRuhpuSoZ9zVmZKS+fqv'
        '1dcIeh4EPA8VaXu6KD70pjUoYwMtPNJJqqEsOm9IH8c4NEcNKhlbAE9tL7QzjTEvqcOHpFKTL4DJ'
        'WolO0rqzMPJgFH1XtwaDQ/xNe2AQX7fJa70LwoE3ViG6qGvGBAMYCnrXQ1HO9+CMWGJ2HrtbHhXf'
        'qieP7gGObS4zDsxy90PLgtFILJ6dAWsag/MenCJTCbbtRfNoE2Ltq5vSw5vvCjHcyYkZ4tzJN865'
        'FYsySNLgTN055iuBhhGar17si2pVT6PDVB45roIzivQ5pPxg6j5HSKQX3DCv/bgWif/75i6oyl0x'
        'FPBf+1yX6L1NkeOWQU8rQ5w2AkT808+PO/k2mfD+c5oGgTpigNa7AH3gFv/MxoZfjdePn7v63iCO'
        'CxywiwfGcWXdVF5dx1ixjTx2xOJFarzawytkkmGmp0UjGRFc2Fp499lxurq8P3hpgY38Q8h5Izse'
        'JXHSzXfi2qLDPcn6x6w94SQ80aGnHRH5Qgitc5CbTzpFa609fKsEEaFDAa/5/IBRuj4v/QIEy4YB'
        'D6Wk3FdiAWl9D0WT2irbtuc1yahdq8c9SasCNUDss1Z3gTuzMAHnEzqMNjhPAlYXqCQFXmFjYoxr'
        'ZtcyZOeOUgPEAf4HOT15a5G/Vm/2S8CLPUjIcDNsRxoWQc0hUuCtRQYK2D2S2LWi6qEGom8OgWU+'
        'Pov9NOfORYBTKCO/GHSyb4cOxWfRjIOABeeb+f8OroBN17frnKOrBI3gZrL0Pk1ssuGboy8AHSxc'
        'YTGHGHL4CpDD3/+eWFgB7DqZ+Cff2Se/a8y7irhIQCw5pohlp+107joLZac/F4zC3WBi2V7ES5DA'
        'NoeN+3gIpeD1cjzIDXo1QjEzXAbmZGaRlSZQ5txm8Sqq443ZgGVtjKkD6BS9trlNuCNiNr7IJJYz'
        'I3wscBjwGOU/eEhnBqAwXLl811hhJSgpXoPD3fR4EZTV62p4xSo4MIaTREtdwMeUEyWBtBcuRRl3'
        'wdiOAqiCrBDXUzcd56wK0BRuutXkrhwrEl54/rUW1JfMWjkLL5q9h9uzM/qLryb3VpSYx7h2Qr8y'
        'TZ75YMSCQxSRSaW1R+peZTitEKhPXrhuEB2gdnJvL+eJ7qUbG6+QbmyXnGeMeUXqWjZC/dseISkN'
        'RXumPcdXfKKjP0sjZ/t+1L7K4uDsXHqPzF5FP0cg/mFkjE4/Psf5TMTMIYe3dy7PI7vDofxnYvMG'
        '8QQr3O86kIgiazt385vxh9YEy4Q0ExAQknxrmFMhzLzBKR4SWZYXVnQ81sU1zU9ITMKNWdRV1kXX'
        'M4QHNltOhQcSsg1dy8+FLT9PghCLzfbGjYHER5irnLZkpVmnaFi0MatifW0b5arz5KfswsijpzY3'
        '0b17LK8XApoZp3eleW+PN8hCalx4TnLDTgtZaIig1aWgn9e/tDYwNrh9JO/fcC766xt0+oxPR+V/'
        'ny18Yo2ZsOXw6tEHpVFXkM9Z5ZxplXIwD3zXdl8tz5u6qndyxW1Mlqmg4ygaCYPcnZEaO5cU1RyZ'
        'iPQnYDrWYOTa6zU3lX82bgNhz4K9SSF3lCUZHZScRUwGYdvKWRLneXTPZnzbdnOBxxFkqceSQfZK'
        'd9vsnrfq3mi//iBXTmd757L37uUC2delTQ3K1ewtR6RziBqcJ98RQePATmBWbXiefNSc7briU2Xy'
        'wLcWrhBGBPHM5C4k9/fDcdTLNTXJ4AMZTjXC/xXovZlGOdqjKjf2Khzj0FnrFuoxta79LPTND8eQ'
        'U8+o6els4aLLpHzKK0IGz/9LUYa9ksAEjIh++bOcBh+EsFbs7xxO5y0QhN55kA6tI6x8dFDSOobG'
        'LhwSk7P6W+jPcTGnhR7bdzbWOecgjKL1ZobJe/rx6/5917beNUub2LDbLyTKmCNm9FsXICyEBYlB'
        'wC50fA/KXytFDIGF8/j8lq/BwjfCIYkdgCqL3AZS6JUr5OzSzHN8BYTY/yjK4qz9Z/ayiX6Ug1pd'
        'n7vB6jzEsJFkdtwKNduaWPXDjBB2J+Vf6cXXxF6Ql2ZlBpyxgZvhnC9p8iKyb9pkyltoVc+MGjEM'
        'l3MCiYVL9+JXZl3WZxlOqDVukm0t22kPmzxrsgrpHVhLyR5z0qFAruuNLrAc3G2VRVNmdzsmSZuM'
        '6Qh1pSf4MbXJ2yVvn17DHrQ9V5BHSWEWhATRygcRQY5YLM6F1z4UiX5JIkZ8tuTxY11fDQbCKE6p'
        'xGiabLm32cfoAvaUYLa6hMByRqyibxCRp8UHuxgSx6RC09oooyGJoWFDP47lywvu+OTrtg9sRwav'
        'uktoSA2nhVVtrTnmeASEDyk6Bc4SOEILuwt1ysyNmNoVovuBxuitS1aveY1sQ3WXXFT1JV8f4gu6'
        'kqwIkY0aq6r+hHVGZP1s9oa+ERfZumwL9tP6jiVtCDL3u9xt2IAg/0ZQRFNwBBt58Esgw82ucLI1'
        '+jmGKBJxJOf37xTzukaHg6zjOAAR9PK5BVwkuO17DljOAPdzk3v4r55BpKvcXG6dDG+nB2zYAOEJ'
        'RnwkzwNuCiz6MFat7UiBnwFEcMBBrVlK+nFskHxKrn33YECbB52zWd/X8FCsHUBKrT7VUybdm8l6'
        'OdEL01F2omlRM9k9BTzQhEgb3xQLUhZqdEl3/sHffreJKkjabpGJpncgOYaYR2FrtJJ8QKmkfmOP'
        '5GIn6HbcV6OeBdFVmGAl957HYBp/61LCqDkzFNeNAsrYIuoNw9vOasMMzWcXTxvvkU7LJYqTWzMx'
        'WKRtMuaE733xeXodj0ru8Xa9gc204d7O9l314IRrJRg5dH4qbXG+q+ksyiOVWn1jswa6F+6yc9Cx'
        '3bu+Eksus1JhubHoZdY94BMOzvU3ofGFH4fCRze2V9kSn3gwV8irKFbVim+kVUsaoHGgjz0BsFig'
        'GC1z+RAH3zWhWoqVBzmvfLaPV9oQ+uAYU+uz6bIcgJQGeFKgVR1ueRuSZEmB8wEOKNgfzlIbNlhC'
        'bCCbKGCIOvUtZwmwgvF8PDSGyQAl75IBJTVWg2wQauv18zip0SCGbIjDoZULsxeQCgN78+7Fzy9e'
        'P3npPgglpkQ4jIoPNKYtnzrxKOd8EEMrlUsqMb4gA5EdmDkzl8MlyGEqV/Vz/uJFJQcsRpMpci8W'
        'JxuzvKJTMLlKF33Xhzepz2W3mLhisdkaL6z1FpsgPpcv9yix6exysg0bx6yPXnMJD86vUeHmTio1'
        'yhZUtHymGTijoRXb+2KRH6fkM2oKdlZ7YyUL9kjj6//xoHnIFJeg12WCErYUszifaTHGkfplIgua'
        'i7bUkvH7zyuJmchrG3Afl7JX4IeJOYKsEmFKDps5uN9VjLXyAvpcQHnir5w78d0UddO/qoB6pJzl'
        'XWBs8YN0mNLLP59rdrGZKz2aAyx6FWQim0VfVhgMSa4z2CWMti5MpCt+u8sh6jP6iA8eLbGu5JAM'
        'ohxKoww65MHBAn9hppkgw/RofmlvL9nJ2c2fctURwh1LI+OXT0g6XDsW1mGGLM6zoB+U8mvKx2gL'
        'n2qLHtkMWnpK45QnhD89KEVwRwsdLH7AXJ9f+S8UjYNtQXzfPymb1RftGqeicuskSyvp23yK38J/'
        '5EesSezIMe+INsGrKTnBd4L7cl5ba77KbYHMq1obLKPVJZGuzaEUm8RiKPEHdR0Mw9fXYCKVe20h'
        'a8cP/rLyEl1LJhm+/ZomzwVDgz+vtf38+ZMMnEAcHwwRs8p/jMN+YUmi2iSlivYfUKlNsvWby75r'
        'yvQvh3JsQeCRXCzatwKDMk6Ds4XT3z6kzs7VGKVHWk6q3hPBdrqVr85MZyE8c49JihoJn/lwJH6p'
        'yd8/l+Lpn56cCn0jIZUgUXjphEaR36bIDouOvvRR4xnay4kDOVLly19iZjvDOPzejH7Nbu6Nbv9m'
        'uq25jsvlKhLcUoU1ppU2ZZ00t6zkdXPRKvoxC/tZDLnkiE95ISOGqAs2IhVJCrMB2htTVpwpUsq2'
        'ax0k13YqeUQwD5Pa/SM6JUw1zfTrz7FAY96ptkMR7yPWFG2w8T3T7BZOGjnBlEOFKhrQIYY6VB0z'
        'CuHayrq7/BHeELjdxFPxvVnm6hlZoytgg3Mz50Dpp4NwQS4mHE5y+dNBElhIPjshXE8p3FghOGQW'
        '5bqVUwNPNfPkvL7k5shEodEh1IopWL+1LW213kXSGKsx9EL8RqPuLGSVAvSW56w/iihWMBHf/SYN'
        'U2saNxH3mGSe23wBqEtkx0yKvEw2h6jG0bp4Ec3M93WcijNxaVhwlOH5U+LOsNISt3YbYzquXJBX'
        'uiWakUwctD+Sqr6UZCNyTHpu2gJrIo/p/zkjiL08b7+soHc5bTRzj3OH7DLGv23SPxw+bK0MzA/J'
        'gKknBmy+TGdBJkxJZimtIN/zQm80MzG8qdymTqkFjaR1FnT8jZFA14hZ3WM1aRK2FvEoNxfzm1V6'
        'hxqNx/rnrFnY2N8TYoUMu4VWOV08jvfvONaAg/1gBzGt3WXts8pwjCFroPD2MV8yGcfvDmGBQ/SF'
        '823gQr1gKqA20XcQIlYoMCaRacioRT8kRv0MNMzcpAazpL6xpxmcriNjSKRe9WeQ2FkpuKakGmxh'
        'RmZgj+SiuJks+CLZ2cj35P0prIWrLYJHZc/0b5tSICSXCH20a6Wf3NLsjCUnyuNwZq75SANpN7hs'
        'LXdzJBlowZ+5VGnnc5/Yyx8hooCEoza5QES9+FKU55lZb02Y7+CE6wd8KqVJp6QcwUZf0KEq/HFC'
        'WY5hvL0u3JKz2frC2rh42F3j44OWn7xWFJrw5ql8Pg7l0+el2UxdYDl/PWO0DTBOHrbgclznKlWw'
        'MnECbP991b48GXLYuc387pWa00P8KXNJcmjrY1AL4QO101q3qW7bbcpswcCt2pGmhspnrsI7NODS'
        '5JcKUJN8xd3um5qSEW2EwrJPH+6zTv9kqnDJt3Fwx8syRhrpL8glUO75bpTrzo02+FIjq2+7Y5Ed'
        'Y1N2ZoG9GpkaY3aCW59Iy0EXhb70rVrrFlU1D3SB+/sp8k66X5g/f1nzyKkXtNl3qqwGiDwWN+Vx'
        'mCIWHG7qAXiv6LKLO6gE+eYUp6MguWDvtQu3kBPjrLN5MjhUI+tuDysJzynmEvXOkbn7QbxGGPtg'
        'm+Q4Ag6hSJOXMB1bzpUPH8lYewwgWt0dOzg/UGMCMExdiAXzc3ZWf5L7YkeS1k/SQpxJhoLAycHR'
        'vb3e0fMdg886/suQGrWRvKFPnuyRjacY8N6YN8GhFhfr0JMYCcBQ9aqxIGO+BtUY+kpI5eLDNW6r'
        '5cjZW0Yjl3QkxXjrP5XCITe5u1/jraou8dzkZdlHK8m6cfkSijP3qTodmYdnLRoNA0s+MW86/73U'
        'za7L+DREkqnr2AJwly2SwacFf89XD7LZt/jnzIZCXPizgsx98eAi+uJBr9jZgWLxhxHEqAoyaDMo'
        'NfJ9xPCrMcJXBz+mIk3YkcefNtLmMTRpxcUQKC9X4i73P6eiH3wM9XzrPgMafZE+PLlq3UXRB3L5'
        'yJXl27bAXdPkraZQtE/s98sZgHly8t6JqEfyUXQWnThdXu7pQfJtr2XJBdT4O6rH9gOqqAevT007'
        'mx1PBWYwbPc50Ghi07ZZ4hvk+86E9305Jsx1HsQv3/IFQVyIg9IPviTom5BPCWIjqUPsIl/Kx9mf'
        'aT7aP0he8L+0TfqG5FjR8e1NchGbpZ6XhcWf6gLP/Ad+Pe5E45y7z0zAbLDNouZUI2C68HN1z9/8'
        'JF5VL2tsVOjpm1evnr/mj9rha5c6x6l2ZN0yv3yOHP0zCb844Z3BjfB8wfEW4QfF7TTsF8dt87N+'
        '1hDf6sGvIo9+b1G2fRrdoQpHyJlS7vQpxujjn73luMP1xLdktRRXtgI+ogWWmMzYNry1mDLKBCP4'
        'v5nBOx8=',
    ),
    'budget_conservative': (
        '1ecebba2de0ffe1a58e393e0559fe31c5bdf963e697353ff9153989a91ceeb61',
        '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'
        '8pAebS99jMn0z8mTXQUfO3behZr4Ryf/F6Yq/cs=',
    ),
    'budget_scope': (
        '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'
        'nf9P9SHo57za5bWE4TRgONWxBz3eap79DwDUwfo=',
    ),
}


def frozen_blob(name):
    """Decompress and hash-verify one embedded original blob."""
    digest, payload = FROZEN_BLOBS[name]
    text = zlib.decompress(base64.b64decode(payload)).decode('utf-8')
    if hashlib.sha256(text.encode()).hexdigest() != digest:
        raise AssertionError('frozen blob %s does not match its recorded '
                             'sha256; the embed is stale or corrupted' % name)
    return text


def gremlins_binary():
    """Locate the Gremlins binary the critical gate pins and versions."""
    found = shutil.which('gremlins')
    if found:
        return found
    local = Path.home() / 'go' / 'bin' / 'gremlins'
    return str(local) if local.is_file() else None


def fixture_package():
    """A critical package path of this repository's own gate config."""
    config = json.loads((Path(critical.__file__).parent / 'critical.json').read_text())
    return config['critical_paths'][0].split('/**')[0]


def run_guarded(argv, cwd, timeout, env, grace=5.0):
    """Timed subprocess in its own process group; timeout kills the group.

    A plain subprocess.run timeout reaps only the direct child, so a
    timed-out `go test` leaves its test binaries running under the
    caller's lease. Every guarded run starts a new session, so the group
    identity is fixed at launch and never needs a racy getpgid lookup.
    On timeout, escalation follows surviving group members, never the
    parent's exit: TERM first, then KILL once the group outlives its
    grace, and the caller resumes only when the group is provably empty
    — a parent that dies to TERM immediately must not hide a
    TERM-resistant descendant. Every wait is bounded; a group that
    survives KILL fails loudly instead of hanging or being abandoned.
    Every exceptional exit closes both pipe descriptors explicitly — a
    retained exception keeps this frame reachable, so waiting for
    garbage collection would leak the descriptors to the caller.
    """
    proc = subprocess.Popen(argv, cwd=str(cwd), text=True, env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    group = proc.pid

    def drained(budget):
        """True once no member of group remains within budget seconds."""
        deadline = time.monotonic() + budget
        while True:
            proc.poll()  # reap a dead parent so it stops holding a group slot
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    try:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(group, sig)
                except ProcessLookupError:
                    break
                if drained(grace):
                    break
            else:
                raise AssertionError(
                    'guarded subprocess group %d still alive after kill'
                    % group) from None
            if proc.poll() is None:
                try:
                    proc.communicate(timeout=grace)
                except subprocess.TimeoutExpired:
                    raise AssertionError(
                        'guarded subprocess %d unreapable after group kill'
                        % proc.pid) from None
            raise
        return subprocess.CompletedProcess(argv, proc.returncode, out, err)
    finally:
        # communicate() owns the pipes on success; on every exceptional
        # exit both descriptors are closed here and now. A retained
        # exception keeps this frame — and its Popen pipes — reachable,
        # so garbage collection would never release them; the close must
        # not depend on it, on a later communicate(), or on poll().
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


class CriticalScopeControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-scope-control-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pkg = self.root / 'pkg/auth'
        self.pkg.mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.test/critical\n\ngo 1.27.4\n')
        self.file = self.pkg / 'auth.go'
        self.file.write_text('package auth\nfunc Allowed(n int) bool { return n > 0 }\nfunc Neighbor() bool { return true }\n')
        for argv in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=self.root, check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        # These controls assert the legacy selector reached only through the
        # explicit CRITICAL_SCOPE_SELECTOR=legacy override; pin the mode so an
        # ambient value cannot change what they verify.
        self.previous_mode = os.environ.get(critical_scope.MODE_ENV)
        os.environ[critical_scope.MODE_ENV] = critical_scope.LEGACY
        if self.previous_mode is None:
            self.addCleanup(os.environ.pop, critical_scope.MODE_ENV, None)
        else:
            self.addCleanup(os.environ.__setitem__, critical_scope.MODE_ENV, self.previous_mode)

    def selected(self):
        return critical_scope.targets(self.root, self.base, {'critical_paths': ['pkg/auth/**']})

    def test_changed_body_selects_only_affected_function(self):
        self.file.write_text(self.file.read_text().replace('n > 0', 'n >= 0'))
        self.assertEqual([fn['name'] for fn in self.selected()['pkg/auth']], ['Allowed'])

    def test_formatting_does_not_select_untouched_debt(self):
        self.file.write_text(self.file.read_text().replace('return n > 0', '\n// durable comment\nreturn n > 0'))
        self.assertFalse(self.selected())

    def test_test_change_selects_production_consumers(self):
        (self.pkg / 'auth_test.go').write_text('package auth\nimport "testing"\nfunc TestAllowed(t *testing.T) { if !Allowed(1) { t.Fatal("denied") } }\n')
        self.assertEqual({fn['name'] for fn in self.selected()['pkg/auth']}, {'Allowed', 'Neighbor'})

    def test_comment_only_test_edit_does_not_reopen_legacy_package(self):
        (self.pkg / 'auth_test.go').write_text('package auth\n// explanation only\n')
        self.assertFalse(self.selected())

    def test_build_mode_selects_only_compiled_functions(self):
        (self.pkg / 'spi.go').write_text('//go:build spi\n\npackage auth\nfunc SPI() bool { return true }\n')
        functions = self.selected()['pkg/auth']
        out = self.root / 'logs'
        out.mkdir()
        self.assertFalse(critical.active_functions(self.root, 'pkg/auth', functions, '', out, time.monotonic() + 20))
        self.assertEqual([fn['name'] for fn in critical.active_functions(self.root, 'pkg/auth', functions, 'spi', out, time.monotonic() + 20)], ['SPI'])


class ConservativeScopeControls(unittest.TestCase):
    """Default conservative selector: binding over widening, never silent."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-conservative-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pkg = self.root / 'pkg/auth'
        self.pkg.mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.test/critical\n\ngo 1.27.4\n')
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func Guarded(n int) bool { return n > 0 }\n')
        (self.pkg / 'state.go').write_text('package auth\n\nvar state = false\n')
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestAllowed(t *testing.T) { if !Allowed(6) { t.Fatal("denied") } }\n')
        (self.pkg / 'fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzAllowed(f *testing.F) {\n\tf.Add("")\n\tf.Fuzz(func(t *testing.T, in string) { Allowed(len(in)) })\n}\n')
        (self.pkg / 'guarded_fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzGuarded(f *testing.F) {\n\tf.Add(1)\n\tf.Fuzz(func(t *testing.T, n int) { Guarded(n) })\n}\n')
        corpus = self.pkg / 'testdata/fuzz/FuzzAllowed'
        corpus.mkdir(parents=True)
        (corpus / 'entry1').write_text('go test fuzz v1\nstring("seed")')
        for argv in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=self.root, check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        self.previous_mode = os.environ.get(critical_scope.MODE_ENV)
        os.environ[critical_scope.MODE_ENV] = critical_scope.CONSERVATIVE
        if self.previous_mode is None:
            self.addCleanup(os.environ.pop, critical_scope.MODE_ENV, None)
        else:
            self.addCleanup(os.environ.__setitem__, critical_scope.MODE_ENV, self.previous_mode)

    def selected(self):
        return critical_scope.targets(self.root, self.base, {'critical_paths': ['pkg/auth/**']})

    def names(self):
        return {fn['name'] for fn in self.selected()['pkg/auth']}

    def reasons(self):
        return critical_scope.selection_evidence()['pkg/auth']['reasons']

    def commit(self, message):
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-qm', message], cwd=self.root, check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()

    def test_changed_body_selects_only_changed_function(self):
        (self.pkg / 'auth.go').write_text((self.pkg / 'auth.go').read_text().replace('n > Limit', 'n >= Limit'))
        self.assertEqual(self.names(), {'Allowed'})

    def test_comment_only_edit_selects_nothing(self):
        (self.pkg / 'auth.go').write_text((self.pkg / 'auth.go').read_text().replace('func Allowed', '// note\nfunc Allowed'))
        self.assertFalse(self.selected())

    def test_removed_test_selects_former_consumers(self):
        (self.pkg / 'auth_test.go').unlink()
        self.assertEqual(self.names(), {'Allowed'})
        self.assertIn('removed test coverage: TestAllowed', self.reasons()['Allowed'])

    def test_unrelated_test_addition_narrows_selection(self):
        (self.pkg / 'neighbor_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNeighbor(t *testing.T) { Neighbor() }\n')
        self.assertEqual(self.names(), {'Neighbor'})

    def test_new_test_target_without_consumers_widens(self):
        (self.pkg / 'void_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNothing(t *testing.T) { t.Log("nothing") }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertTrue(self.reasons()['*'])

    def test_removed_test_without_consumers_widens(self):
        (self.pkg / 'void_test.go').write_text(
            'package auth\n\nimport "testing"\n\nfunc TestVoid(t *testing.T) {}\n')
        self.commit('void target')
        (self.pkg / 'void_test.go').unlink()
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertTrue(self.reasons()['*'])

    def test_helper_weakening_keeps_binding_narrow(self):
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func help() bool { return Allowed(6) }\n\n'
            'func TestAllowed(t *testing.T) { if !help() { t.Fatal("denied") } }\n')
        self.commit('helper')
        (self.pkg / 'auth_test.go').write_text((self.pkg / 'auth_test.go').read_text().replace('Allowed(6)', 'Allowed(7)'))
        self.assertEqual(self.names(), {'Allowed'})

    def test_helper_dropping_reference_widens(self):
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func help() bool { return Allowed(6) }\n\n'
            'func TestAllowed(t *testing.T) { if !help() { t.Fatal("denied") } }\n')
        self.commit('helper')
        (self.pkg / 'auth_test.go').write_text((self.pkg / 'auth_test.go').read_text().replace('return Allowed(6)', 'return true'))
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertTrue(any('no bindable production consumer' in reason
                            for reason in self.reasons()['*']))
        self.assertEqual(critical_scope.selection_evidence()['pkg/auth']['rebaselined'],
                         ['help → Allowed'])

    def test_global_state_reference_widens(self):
        (self.pkg / 'state_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestState(t *testing.T) { if state { t.Fatal("set") } }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_indirect_dispatch_reference_widens(self):
        (self.pkg / 'dispatch_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestDispatch(t *testing.T) {\n'
            '\tvar h struct{ Allowed func(int) bool }\n'
            '\th.Allowed(1)\n}\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_concrete_method_consumer_stays_narrow(self):
        """A concrete local method call is a definite reference, not
        dispatch: a test edit selects only the consumed method's unit
        instead of reopening the package."""
        (self.pkg / 'gate.go').write_text(
            'package auth\n\n'
            'func (g *gate) Open(n int) bool { return n > 0 }\n\n'
            'type gate struct{}\n')
        (self.pkg / 'gate_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestGate(t *testing.T) {\n'
            '\tvar g gate\n'
            '\tuse := func() bool { return g.Open(1) }\n'
            '\tif !use() { t.Fatal("closed") }\n}\n')
        self.commit('gate consumer')
        (self.pkg / 'gate_test.go').write_text(
            (self.pkg / 'gate_test.go').read_text().replace('t.Fatal("closed")', 't.Fatal("shut")'))
        self.assertEqual(self.names(), {'Open'})

    def test_pointer_promoted_method_stays_narrow(self):
        """Pointer-indirection promotion is not dynamic dispatch: a call
        through an embedded pointer stays an exact reference."""
        (self.pkg / 'gate.go').write_text(
            'package auth\n\n'
            'type base struct{}\n\n'
            'func (b *base) Open(n int) bool { return n > 0 }\n\n'
            'type gate struct { *base }\n')
        (self.pkg / 'gate_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestGate(t *testing.T) {\n'
            '\tg := &gate{base: &base{}}\n'
            '\tif !g.Open(1) { t.Fatal("closed") }\n}\n')
        self.commit('pointer promotion')
        (self.pkg / 'gate_test.go').write_text(
            (self.pkg / 'gate_test.go').read_text().replace('t.Fatal("closed")', 't.Fatal("shut")'))
        self.assertEqual(self.names(), {'Open'})

    def test_embedded_interface_dispatch_widens(self):
        """Methods promoted through an embedded interface stay dynamic:
        calling one named like a package function reopens the package."""
        (self.pkg / 'hook.go').write_text(
            'package auth\n\n'
            'type opener interface{ Allowed(n int) bool }\n\n'
            'type gate struct{ opener }\n')
        (self.pkg / 'gate_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestGate(t *testing.T) {\n'
            '\tvar g gate\n'
            '\tif !g.Allowed(1) { t.Fatal("denied") }\n}\n')
        self.commit('interface promotion')
        (self.pkg / 'gate_test.go').write_text(
            (self.pkg / 'gate_test.go').read_text().replace('t.Fatal("denied")', 't.Fatal("no")'))
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_foreign_call_does_not_reopen_via_name_collision(self):
        """A foreign package function (http.Get) never collapses into the
        local Get: editing its consumer keeps only the genuine binding."""
        (self.pkg / 'get.go').write_text(
            'package auth\n\nfunc Get() bool { return state }\n')
        (self.pkg / 'foreign_test.go').write_text(
            'package auth\n\nimport (\n\t"net/http"\n\t"testing"\n)\n\n'
            'func help() bool { _, _ = http.Get("x"); return Allowed(6) }\n\n'
            'func TestForeign(t *testing.T) { if !help() { t.Fatal("denied") } }\n')
        self.commit('foreign consumer')
        (self.pkg / 'foreign_test.go').write_text(
            (self.pkg / 'foreign_test.go').read_text().replace('Allowed(6)', 'Allowed(7)'))
        self.assertEqual(self.names(), {'Allowed'})

    def test_local_shadow_does_not_widen_global_state(self):
        """A local shadow is not a reference to the global it names.

        The helper carries a genuine Allowed binding, so the narrow set
        is a real contract; the shadowed local must not reopen the
        package through state vars. Rebinding the same helper to the
        real global proves the opposite direction: the widen fires.
        """
        (self.pkg / 'shadow_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func help() bool { state := true; return Allowed(6) && state }\n\n'
            'func TestShadow(t *testing.T) { if !help() { t.Fatal("denied") } }\n')
        self.commit('shadow consumer')
        (self.pkg / 'shadow_test.go').write_text(
            (self.pkg / 'shadow_test.go').read_text().replace('t.Fatal("denied")', 't.Fatal("no")'))
        self.assertEqual(self.names(), {'Allowed'})
        (self.pkg / 'shadow_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func help() bool { return Allowed(6) || state }\n\n'
            'func TestShadow(t *testing.T) { if !help() { t.Fatal("denied") } }\n')
        self.commit('global consumer')
        (self.pkg / 'shadow_test.go').write_text(
            (self.pkg / 'shadow_test.go').read_text().replace('t.Fatal("denied")', 't.Fatal("no")'))
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_global_receiver_reference_widens(self):
        """A package-global receiver reached through a selector keeps its
        global-state widening: only import qualifiers may be skipped as
        bare identifiers."""
        (self.pkg / 'gate.go').write_text(
            'package auth\n\n'
            'type gate struct{}\n\n'
            'func (g gate) Open(n int) bool { return n > 0 }\n\n'
            'var gateRef = gate{}\n')
        (self.pkg / 'gate_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func help() bool { g := gateRef; return g.Open(1) }\n\n'
            'func TestGate(t *testing.T) { if !help() { t.Fatal("closed") } }\n')
        self.commit('global receiver')
        (self.pkg / 'gate_test.go').write_text(
            (self.pkg / 'gate_test.go').read_text().replace('t.Fatal("closed")', 't.Fatal("shut")'))
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded', 'Open'})

    def test_foreign_factory_callback_closure_keeps_deny_coverage(self):
        """A factory wiring a local callback into a foreign adapter owes
        the callback's coverage: a test rewrite that drops the deny case
        still selects NewGate together with deny through the production
        effect closure, so deny coverage cannot silently disappear."""
        adapter = self.root / 'pkg/adapter'
        adapter.mkdir()
        (adapter / 'adapter.go').write_text(
            'package adapter\n\ntype Adapter struct{ Check func(n int) bool }\n')
        (self.pkg / 'factory.go').write_text(
            'package auth\n\n'
            'import "example.test/critical/pkg/adapter"\n\n'
            'func deny(n int) bool { return n > 0 }\n\n'
            'func NewGate() adapter.Adapter { return adapter.Adapter{Check: deny} }\n')
        (self.pkg / 'factory_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestFactory(t *testing.T) {\n'
            '\tg := NewGate()\n'
            '\tif !g.Check(1) { t.Fatal("allowed through") }\n}\n')
        self.commit('factory')
        # Fully covered positive: a trivial rewrite keeps the deny case,
        # so the factory and its callback stay selected and narrow.
        (self.pkg / 'factory_test.go').write_text(
            (self.pkg / 'factory_test.go').read_text().replace(
                't.Fatal("allowed through")', 't.Fatal("still allowed")'))
        self.assertEqual(self.names(), {'NewGate', 'deny'})
        # Dropped-deny rewrite: the deny obligation the baseline carried
        # must block loudly — lost_unit_coverage naming deny — instead of
        # letting its coverage disappear with the rewrite.
        (self.pkg / 'factory_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestFactory(t *testing.T) { _ = NewGate() }\n')
        with self.assertRaises(ValueError) as blocked:
            self.names()
        self.assertIn('lost_unit_coverage: pkg/auth: TestFactory', str(blocked.exception))
        self.assertIn('deny', str(blocked.exception))
        # Different-consumer rewrite: the baseline twin's factory
        # coverage — deny included through the baseline effect closure —
        # blocks the same way, never silently dropped.
        (self.pkg / 'factory_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestFactory(t *testing.T) { Neighbor() }\n')
        with self.assertRaises(ValueError) as blocked:
            self.names()
        self.assertIn('lost_unit_coverage: pkg/auth: TestFactory', str(blocked.exception))
        self.assertIn('deny', str(blocked.exception))

    def test_internal_type_error_floors_without_narrowing(self):
        """An internal-test type error floors the mode closed: the helper
        exits cleanly with a fallback note and name-based references,
        never panicking and never resolving the target package from
        production export data instead of the failed test package."""
        (self.pkg / 'broken_test.go').write_text(
            'package auth\n\nfunc brokenHelper() bool { return undefinedSymbol }\n')
        (self.pkg / 'external_test.go').write_text(
            'package auth_test\n\nimport (\n'
            '\t"example.test/critical/pkg/auth"\n\t"testing"\n)\n\n'
            'func TestExternal(t *testing.T) { if !auth.Allowed(1) { t.Fatal("denied") } }\n')
        helper = Path(critical.__file__).parent / 'units.go'
        request = json.dumps({'paths': ['pkg/auth/auth.go', 'pkg/auth/state.go',
                                        'pkg/auth/broken_test.go',
                                        'pkg/auth/external_test.go'], 'modes': None})
        env = dict(os.environ, GOWORK='off', GOFLAGS='', GOTOOLCHAIN='go1.27.4')
        run = subprocess.run(['go', 'run', str(helper)], input=request, cwd=self.root,
                             capture_output=True, text=True, env=env, timeout=110)
        self.assertEqual(run.returncode, 0, run.stderr[:400])
        rows = {row['path']: row for row in json.loads(run.stdout)}
        # Both test files must floor with fallback notes: the internal
        # group's type errors must not let the external group resolve the
        # target package from production export data.
        for path in ('pkg/auth/broken_test.go', 'pkg/auth/external_test.go'):
            notes = rows[path].get('resolution') or []
            self.assertTrue(any('resolution-fallback' in note for note in notes),
                            (path, notes))
        allowed = next(u for u in rows['pkg/auth/auth.go']['units'] if u['name'] == 'Allowed')
        self.assertIn('Limit', allowed.get('refs') or [])
        external = next(u for u in rows['pkg/auth/external_test.go']['units']
                        if u['name'] == 'TestExternal')
        self.assertIn('Allowed', set(external.get('refs') or [])
                      | set(external.get('selrefs') or []))

    def test_function_field_capture_widen_not_concealed(self):
        """MV-01: capturing a function-valued field keeps its dynamic
        obligation. The genuine Guarded consumer in the same body proves
        the omission is concealed narrowing rather than empty-consumer
        widening: without the field obligation the edit would select only
        Guarded and silently drop Allowed's uncertainty."""
        (self.pkg / 'hook.go').write_text(
            'package auth\n\ntype Hook struct{ Allowed func(int) bool }\n')
        (self.pkg / 'fnvalue_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestFnValue(t *testing.T) {\n'
            '\tvar h Hook\n'
            '\th.Allowed = func(n int) bool { return Guarded(n) }\n'
            '\tfn := h.Allowed\n'
            '\tif !fn(1) { t.Fatal("denied") }\n}\n')
        self.commit('field value consumer')
        (self.pkg / 'fnvalue_test.go').write_text(
            (self.pkg / 'fnvalue_test.go').read_text().replace('t.Fatal("denied")', 't.Fatal("no")'))
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertTrue(any('references indirect dispatch' in reason
                            for reason in self.reasons()['*']))

    def test_method_value_capture_stays_narrow(self):
        """MV-01 positive: a concrete local method-value capture binds
        exactly; the dynamic-uncertainty rule for func-valued fields must
        not leak into method values."""
        (self.pkg / 'gate.go').write_text(
            'package auth\n\ntype gate struct{}\n\n'
            'func (g gate) Open(n int) bool { return n > 0 }\n')
        (self.pkg / 'methvalue_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestMethodValue(t *testing.T) {\n'
            '\tvar g gate\n'
            '\tm := g.Open\n'
            '\tif !m(1) { t.Fatal("closed") }\n}\n')
        self.commit('method value consumer')
        (self.pkg / 'methvalue_test.go').write_text(
            (self.pkg / 'methvalue_test.go').read_text().replace('t.Fatal("closed")', 't.Fatal("shut")'))
        self.assertEqual(self.names(), {'Open'})

    def test_unresolved_dispatch_rewrite_loss_blocks(self):
        """EFF-01 negative: a rewrite that drops the entry point of an
        unresolved production dispatch still owes the known baseline
        consumer. Widening the uncertain target may not replace the
        real coverage block for the consumer it already knows. Fixture
        limitation: the shared fixture also defines FuzzAllowed and
        FuzzGuarded, so this control exercises only the unit-test
        baseline path and claims nothing about fuzz coverage."""
        (self.pkg / 'dispatch.go').write_text(
            'package auth\n\n'
            'type Dispatcher interface{ Allowed(n int) bool }\n\n'
            'func Dispatch(h Dispatcher, n int) bool { return h.Allowed(n) }\n\n'
            'func Keep(n int) bool { return false }\n')
        (self.pkg / 'dispatch_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'type realHook struct{}\n\n'
            'func (realHook) Allowed(n int) bool { return Allowed(n) }\n\n'
            'func TestDispatch(t *testing.T) {\n'
            '\tif !Dispatch(realHook{}, 6) { t.Fatal("dispatch denied") }\n}\n')
        self.commit('dispatch consumer')
        (self.pkg / 'dispatch_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'type realHook struct{}\n\n'
            'func (realHook) Allowed(n int) bool { return Allowed(n) }\n\n'
            'func TestDispatch(t *testing.T) {\n'
            '\t_ = Keep(1)\n}\n')
        with self.assertRaises(ValueError) as blocked:
            self.names()
        self.assertIn('lost_unit_coverage: pkg/auth: TestDispatch', str(blocked.exception))
        self.assertIn('Dispatch', str(blocked.exception))

    def test_unresolved_dispatch_rewrite_preserving_widens_without_loss(self):
        """EFF-01 positive: a rewrite that keeps the dispatch entry point
        widens for the unresolved target but keeps its coverage, so the
        known baseline consumers verify silently instead of blocking."""
        (self.pkg / 'dispatch.go').write_text(
            'package auth\n\n'
            'type Dispatcher interface{ Allowed(n int) bool }\n\n'
            'func Dispatch(h Dispatcher, n int) bool { return h.Allowed(n) }\n\n'
            'func Keep(n int) bool { return false }\n')
        (self.pkg / 'dispatch_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'type realHook struct{}\n\n'
            'func (realHook) Allowed(n int) bool { return Allowed(n) }\n\n'
            'func TestDispatch(t *testing.T) {\n'
            '\tif !Dispatch(realHook{}, 6) { t.Fatal("dispatch denied") }\n}\n')
        self.commit('dispatch consumer')
        (self.pkg / 'dispatch_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'type realHook struct{}\n\n'
            'func (realHook) Allowed(n int) bool { return Allowed(n) }\n\n'
            'func TestDispatch(t *testing.T) {\n'
            '\tif Dispatch(realHook{}, 1) || Keep(2) { t.Fatal("unexpected") }\n}\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded', 'Dispatch', 'Keep'})
        self.assertTrue(any('reaches unresolved production dispatch' in reason
                            for reason in self.reasons()['*']))

    def test_unresolved_dispatch_removed_test_blocks(self):
        """EFF-01 removed leg: deleting the test that entered the
        unresolved dispatch still blocks on the known consumer instead of
        widening the obligation away."""
        (self.pkg / 'dispatch.go').write_text(
            'package auth\n\n'
            'type Dispatcher interface{ Allowed(n int) bool }\n\n'
            'func Dispatch(h Dispatcher, n int) bool { return h.Allowed(n) }\n\n'
            'func Keep(n int) bool { return false }\n')
        (self.pkg / 'dispatch_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'type realHook struct{}\n\n'
            'func (realHook) Allowed(n int) bool { return Allowed(n) }\n\n'
            'func TestDispatch(t *testing.T) {\n'
            '\tif !Dispatch(realHook{}, 6) { t.Fatal("dispatch denied") }\n}\n')
        self.commit('dispatch consumer')
        (self.pkg / 'dispatch_test.go').unlink()
        with self.assertRaises(ValueError) as blocked:
            self.names()
        self.assertIn('lost_unit_coverage: pkg/auth: TestDispatch', str(blocked.exception))
        self.assertIn('Dispatch', str(blocked.exception))

    def test_interface_declaration_change_widens(self):
        (self.pkg / 'hook.go').write_text('package auth\n\ntype Hook interface{ Run() }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_blank_import_widens(self):
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nimport _ "embed"\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func Guarded(n int) bool { return n > 0 }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_const_change_selects_consumers(self):
        (self.pkg / 'auth.go').write_text((self.pkg / 'auth.go').read_text().replace('Limit = 5', 'Limit = 6'))
        self.assertEqual(self.names(), {'Allowed'})
        self.assertIn('changed constant consumer: Limit', self.reasons()['Allowed'])

    def test_unexported_const_without_consumers_fails(self):
        (self.pkg / 'auth.go').write_text(
            (self.pkg / 'auth.go').read_text().replace('const Limit = 5', 'const Limit = 5\n\nconst unused = 7'))
        with self.assertRaises(ValueError):
            self.selected()

    def test_exported_const_without_consumers_widens(self):
        (self.pkg / 'auth.go').write_text(
            (self.pkg / 'auth.go').read_text().replace('const Limit = 5', 'const Limit = 5\n\nconst ExportedUnused = 7'))
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_last_fuzz_target_removal_fails(self):
        (self.pkg / 'fuzz_test.go').unlink()
        (self.pkg / 'guarded_fuzz_test.go').unlink()
        with self.assertRaises(ValueError):
            self.selected()

    def test_one_fuzz_target_removed_selects_its_coverage(self):
        (self.pkg / 'fuzz_test.go').unlink()
        self.assertEqual(self.names(), {'Allowed'})
        self.assertIn('fuzz target removed: FuzzAllowed',
                      critical_scope.selection_evidence()['pkg/auth']['guards'])

    def test_fuzz_corpus_change_widens(self):
        (self.pkg / 'testdata/fuzz/FuzzAllowed/entry1').unlink()
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertIn('fuzz corpus change', self.reasons()['*'][0])

    def test_shared_testdata_change_widens(self):
        (self.pkg / 'testdata/config.json').write_text('{"v": 2}\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_build_directive_change_selects_file_functions(self):
        (self.pkg / 'auth.go').write_text('//go:build linux\n\n' + (self.pkg / 'auth.go').read_text())
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})
        self.assertIn('build directives changed', self.reasons()['Allowed'][0])

    def test_move_within_package_stays_unselected(self):
        text = (self.pkg / 'auth.go').read_text()
        (self.pkg / 'auth.go').write_text(text.replace('func Guarded(n int) bool { return n > 0 }\n', ''))
        (self.pkg / 'moved.go').write_text('package auth\n\nfunc Guarded(n int) bool { return n > 0 }\n')
        self.assertFalse(self.selected())

    def test_duplicated_function_selected(self):
        (self.pkg / 'moved.go').write_text(
            'package auth\n\nfunc Allowed(n int) bool { return n > Limit }\n')
        self.assertEqual(self.names(), {'Allowed'})

    def test_removed_state_file_widens(self):
        (self.pkg / 'state.go').unlink()
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_stale_base_selects_everything(self):
        empty_tree = subprocess.check_output(['git', 'hash-object', '-t', 'tree', '/dev/null'],
                                             text=True).strip()
        self.base = empty_tree
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_default_mode_is_conservative(self):
        os.environ.pop(critical_scope.MODE_ENV, None)
        (self.pkg / 'neighbor_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNeighbor(t *testing.T) { Neighbor() }\n')
        self.assertEqual(self.names(), {'Neighbor'})

    def test_explicit_legacy_override_selects_package(self):
        os.environ[critical_scope.MODE_ENV] = critical_scope.LEGACY
        (self.pkg / 'neighbor_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNeighbor(t *testing.T) { Neighbor() }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor', 'Guarded'})

    def test_invalid_mode_value_fails(self):
        os.environ[critical_scope.MODE_ENV] = 'aggressive'
        with self.assertRaisesRegex(ValueError, 'aggressive'):
            self.selected()

    def test_body_swap_selects_both_functions(self):
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > 0 }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func Guarded(n int) bool { return n > Limit }\n')
        self.assertEqual(self.names(), {'Allowed', 'Guarded'})
        self.assertIn('changed function: Allowed', self.reasons()['Allowed'])
        self.assertIn('changed function: Guarded', self.reasons()['Guarded'])

    def test_renamed_function_selects_new_name(self):
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func GuardedRenamed(n int) bool { return n > 0 }\n')
        (self.pkg / 'guarded_fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzGuarded(f *testing.F) {\n\tf.Add(1)\n'
            '\tf.Fuzz(func(t *testing.T, n int) { GuardedRenamed(n) })\n}\n')
        self.assertEqual(self.names(), {'GuardedRenamed'})
        self.assertIn('renamed/moved function: GuardedRenamed', self.reasons()['GuardedRenamed'])

    def test_build_tagged_out_test_targets_fail(self):
        for name in ('auth_test.go', 'fuzz_test.go', 'guarded_fuzz_test.go'):
            path = self.pkg / name
            path.write_text('//go:build probe_ignore\n\n' + path.read_text())
        with self.assertRaisesRegex(ValueError, 'fuzz target coverage loss'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_platform_renamed_test_targets_fail(self):
        (self.pkg / 'fuzz_test.go').rename(self.pkg / 'fuzz_windows_test.go')
        (self.pkg / 'guarded_fuzz_test.go').rename(self.pkg / 'guarded_windows_test.go')
        with self.assertRaises(ValueError):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_platform_moved_unit_test_fails(self):
        (self.pkg / 'auth_test.go').rename(self.pkg / 'auth_windows_test.go')
        with self.assertRaisesRegex(ValueError, 'unit-test coverage loss'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_partial_unit_test_move_fails(self):
        (self.pkg / 'neighbor_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestNeighbor(t *testing.T) { Neighbor() }\n')
        self.commit('two unit tests')
        block = 'func TestAllowed(t *testing.T) { if !Allowed(6) { t.Fatal("denied") } }\n'
        (self.pkg / 'auth_test.go').write_text('package auth\n\nimport "testing"\n\n')
        (self.pkg / 'auth_windows_test.go').write_text(
            'package auth\n\nimport "testing"\n\n' + block)
        with self.assertRaisesRegex(ValueError,
                                    r'unit-test coverage loss.*TestAllowed'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_build_tagged_out_unit_tests_fail(self):
        path = self.pkg / 'auth_test.go'
        path.write_text('//go:build probe_ignore\n\n' + path.read_text())
        with self.assertRaisesRegex(ValueError, 'unit-test coverage loss'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_partial_fuzz_target_move_fails(self):
        (self.pkg / 'fuzz_windows_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzAllowed(f *testing.F) {\n\tf.Add("")\n\tf.Fuzz(func(t *testing.T, in string) { Allowed(len(in)) })\n}\n')
        (self.pkg / 'fuzz_test.go').unlink()
        with self.assertRaisesRegex(ValueError,
                                    r'fuzz target coverage loss.*FuzzAllowed'):
            critical_scope.targets(self.root, self.base,
                                   {'critical_paths': ['pkg/auth/**'], 'build_tags': ['']})

    def test_changed_test_rebaselines_still_covered_function(self):
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestAllowed(t *testing.T) { if !Neighbor() { t.Fatal("denied") } }\n')
        self.assertEqual(self.names(), {'Neighbor'})
        evidence = critical_scope.selection_evidence()['pkg/auth']
        self.assertEqual(evidence['rebaselined'], ['TestAllowed → Allowed'])

    def test_coverage_losing_rewrite_fails(self):
        (self.pkg / 'guarded_fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzGuarded(f *testing.F) {\n\tf.Add(1)\n'
            '\tf.Fuzz(func(t *testing.T, n int) { Neighbor() })\n}\n')
        with self.assertRaisesRegex(ValueError, r'lost_unit_coverage.*Guarded'):
            self.selected()

    def test_shifted_lost_coverage_still_blocks(self):
        # Padding that shifts a function beyond its own span must not turn
        # its lost baseline coverage vacuous — the proof runs against the
        # base-revision span, not the current one.
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n' + '// pad\n' * 12 +
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func Guarded(n int) bool { return n > 0 }\n')
        (self.pkg / 'guarded_fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzGuarded(f *testing.F) {\n\tf.Add(1)\n'
            '\tf.Fuzz(func(t *testing.T, n int) { Neighbor() })\n}\n')
        with self.assertRaisesRegex(ValueError, r'lost_unit_coverage.*Guarded'):
            self.selected()

    def test_moved_function_lost_coverage_still_blocks(self):
        # Relocating a function must not dodge the lost-baseline proof
        # any more than shifting it does.
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n')
        (self.pkg / 'moved.go').write_text(
            'package auth\n\nfunc Guarded(n int) bool { return n > 0 }\n')
        (self.pkg / 'guarded_fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzGuarded(f *testing.F) {\n\tf.Add(1)\n'
            '\tf.Fuzz(func(t *testing.T, n int) { Neighbor() })\n}\n')
        with self.assertRaisesRegex(ValueError, r'lost_unit_coverage.*Guarded'):
            self.selected()

    def test_moved_function_rebaselines_with_evidence(self):
        # A moved function the rewrite still covers re-baselines as
        # recorded evidence instead of silently losing its baseline record.
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n')
        (self.pkg / 'moved.go').write_text(
            'package auth\n\nfunc Guarded(n int) bool { return n > 0 }\n')
        (self.pkg / 'guarded_fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzGuarded(f *testing.F) {\n\tf.Add(2)\n'
            '\tf.Fuzz(func(t *testing.T, n int) { Guarded(n) })\n}\n')
        self.assertEqual(self.names(), {'Guarded'})
        evidence = critical_scope.selection_evidence()['pkg/auth']
        self.assertEqual(evidence['rebaselined'], ['FuzzGuarded → Guarded'])

    def test_shifted_benign_rewrite_rebaselines_with_evidence(self):
        # A benign rewrite of a shifted function re-baselines with evidence
        # instead of silently dropping the record.
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n' + '// pad\n' * 12 +
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n\n'
            'func Guarded(n int) bool { return n > 0 }\n')
        (self.pkg / 'guarded_fuzz_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func FuzzGuarded(f *testing.F) {\n\tf.Add(2)\n'
            '\tf.Fuzz(func(t *testing.T, n int) { Guarded(n) })\n}\n')
        self.assertEqual(self.names(), {'Guarded'})
        evidence = critical_scope.selection_evidence()['pkg/auth']
        self.assertEqual(evidence['rebaselined'], ['FuzzGuarded → Guarded'])

    def test_unprovable_consumer_stays_bound(self):
        # A consumer with no resolvable base counterpart (an inlined test
        # helper whose name a new production function reuses) is not
        # vacuous — uncovered, it blocks.
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func resolve() bool { return Allowed(6) }\n\n'
            'func TestAllowed(t *testing.T) { if !resolve() { t.Fatal("denied") } }\n')
        self.commit('helper named like a foreign symbol')
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestAllowed(t *testing.T) { if !Allowed(6) { t.Fatal("denied") } }\n')
        (self.pkg / 'resolve.go').write_text(
            'package auth\n\nfunc resolve() bool { return true }\n')
        with self.assertRaisesRegex(ValueError, r'lost_unit_coverage.*resolve'):
            self.selected()

    def test_stdlib_name_collision_is_not_a_lost_function(self):
        # A rewritten test calling stdlib methods (an httptest recorder's
        # WriteHeader) must not block on same-named production methods the
        # base suite never executed: lost-baseline records bind by bare
        # name, so only base-covered functions count as baseline coverage.
        (self.pkg / 'recorder.go').write_text(
            'package auth\n\ntype recorder struct{ code int }\n\n'
            'func (r *recorder) WriteHeader(code int) { r.code = code }\n')
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport (\n\t"net/http/httptest"\n\t"testing"\n)\n\n'
            'func TestAllowed(t *testing.T) {\n'
            '\trw := httptest.NewRecorder()\n'
            '\trw.WriteHeader(200)\n'
            '\tif rw.Code != 200 || !Allowed(6) {\n\t\tt.Fatal("denied")\n\t}\n}\n')
        self.commit('recorder baseline')
        (self.pkg / 'auth_test.go').write_text(
            'package auth\n\nimport (\n\t"net/http/httptest"\n\t"testing"\n)\n\n'
            'func TestAllowed(t *testing.T) {\n'
            '\trw := httptest.NewRecorder()\n'
            '\tif rw.Code != 200 || !Allowed(6) {\n\t\tt.Fatal("denied")\n\t}\n}\n')
        self.assertEqual(self.names(), {'Allowed'})
        evidence = critical_scope.selection_evidence()['pkg/auth']
        self.assertEqual(evidence['rebaselined'], ['TestAllowed → Allowed'])

    def test_blank_identifier_assertion_is_not_state(self):
        (self.pkg / 'blank.go').write_text(
            'package auth\n\ntype Hook interface{ Run() }\n\n'
            'var _ Hook = hookImpl{}\n\ntype hookImpl struct{}\n\n'
            'func (hookImpl) Run() {}\n')
        self.commit('blank idiom')
        (self.pkg / 'blank_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestBlank(t *testing.T) { _, _ = Allowed(1), Allowed(2) }\n')
        self.assertEqual(self.names(), {'Allowed'})

    def test_widen_selection_demands_fuzz_seeds_for_every_row(self):
        # Restored seed contract: widening is the conservative fallback, so
        # every widened row keeps the historical fuzz-seed demand, and the
        # demand blocks on the function no fuzz seed executes.
        (self.pkg / 'state.go').write_text('package auth\n\nvar state = true\n')
        functions = self.selected()['pkg/auth']
        self.assertEqual({fn['name'] for fn in functions},
                         {'Allowed', 'Neighbor', 'Guarded'})
        self.assertTrue(all(fn['seed'] for fn in functions))
        with tempfile.TemporaryDirectory(prefix='fuzz-seeds-') as tmp, \
                self.assertRaisesRegex(ValueError,
                                       r'Fuzz seeds do not cover.*Neighbor'):
            critical.fuzz(self.root, 'pkg/auth', functions, '', Path(tmp),
                          time.monotonic() + 120, max_fuzz_seconds=1)

    def test_changed_function_without_seed_coverage_fails(self):
        (self.pkg / 'auth.go').write_text(
            (self.pkg / 'auth.go').read_text().replace('return true', 'return false'))
        functions = self.selected()['pkg/auth']
        self.assertEqual([fn['name'] for fn in functions if fn['seed']], ['Neighbor'])
        with tempfile.TemporaryDirectory(prefix='fuzz-seeds-') as tmp, \
                self.assertRaisesRegex(ValueError, 'Fuzz seeds do not cover'):
            critical.fuzz(self.root, 'pkg/auth', functions, '', Path(tmp),
                          time.monotonic() + 120, max_fuzz_seconds=1)

    def test_removed_function_still_referenced_by_test_widens(self):
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor'})
        self.assertTrue(any('removed function still referenced' in reason
                            for reason in self.reasons()['*']))

    def test_reflect_dispatch_literal_blocks_silent_removal(self):
        (self.pkg / 'dispatch_test.go').write_text(
            'package auth\n\nimport (\n\t"reflect"\n\t"testing"\n)\n\n'
            'type holder struct{}\n\n'
            'func TestDispatch(t *testing.T) { reflect.ValueOf(holder{}).MethodByName("Guarded") }\n')
        self.commit('dispatch baseline')
        (self.pkg / 'auth.go').write_text(
            'package auth\n\nconst Limit = 5\n\n'
            'func Allowed(n int) bool { return n > Limit }\n\n'
            'func Neighbor() bool { return true }\n')
        self.assertEqual(self.names(), {'Allowed', 'Neighbor'})
        self.assertTrue(any('removed function in dynamic-dispatch package' in reason
                            for reason in self.reasons()['*']))


@unittest.skipUnless(gremlins_binary(), 'gremlins not installed')
class ConservativeGateControls(unittest.TestCase):
    """The full critical gate passes a test-only rewrite without widening."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-gate-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = fixture_package()
        self.pkg = self.root / self.package
        self.pkg.mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.test/critical\n\ngo 1.27.4\n')
        (self.pkg / 'gw.go').write_text(
            'package auth\n\n'
            'type Handler interface{ Handle(n int) bool }\n\n'
            'var _ Handler = router{}\n\n'
            'type router struct{}\n\n'
            'func (router) Handle(n int) bool { return Allowed(n) }\n\n'
            'func Allowed(n int) bool { return n > 0 }\n\n'
            'func Neighbor() bool { return true }\n')
        (self.pkg / 'gw_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestAllowed(t *testing.T) {\n'
            '\tif !Allowed(1) {\n\t\tt.Fatal("denied")\n\t}\n}\n')
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=self.root, check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                            cwd=self.root, text=True).strip()
        self.previous_mode = os.environ.get(critical_scope.MODE_ENV)
        os.environ[critical_scope.MODE_ENV] = critical_scope.CONSERVATIVE
        if self.previous_mode is None:
            self.addCleanup(os.environ.pop, critical_scope.MODE_ENV, None)
        else:
            self.addCleanup(os.environ.__setitem__, critical_scope.MODE_ENV, self.previous_mode)

    def test_test_only_rewrite_passes_gate(self):
        # A gateway-shaped test-only rewrite: same target, new body that also
        # uses the blank identifier next to a `var _ Handler = ...` idiom.
        (self.pkg / 'gw_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestAllowed(t *testing.T) {\n'
            '\tfor _, n := range []int{1, 2} {\n'
            '\t\tif !Allowed(n) {\n\t\t\tt.Fatal("denied")\n\t\t}\n\t}\n}\n')
        # Gate output stays outside the fixture root: anything inside the
        # tree counts as a source change and must fail the run.
        outbox = tempfile.TemporaryDirectory(prefix='critical-gate-out-')
        self.addCleanup(outbox.cleanup)
        out = Path(outbox.name) / 'gate'
        args = argparse.Namespace(root=self.root, base=self.base,
                                  gremlins=gremlins_binary(), output=out)
        self.assertEqual(critical.run(args), 0)
        report = json.loads((out / 'report.json').read_text())
        self.assertEqual(report['status'], 'passed')
        entry = report['packages'][self.package]
        self.assertEqual([fn['name'] for fn in entry['functions']], ['Allowed'])
        # Coverage-bound selections carry the seed demand too; this package
        # has no fuzz targets, so the demand stays unenforced by policy.
        self.assertTrue(all(fn['seed'] for fn in entry['functions']))
        self.assertEqual(entry['checks']['unit:']['status'], 'passed')
        evidence = report['selector']['evidence'][self.package]
        self.assertIsNone(evidence['widened'])
        self.assertEqual(evidence['rebaselined'], ['TestAllowed → Allowed'])
        owner_proof = evidence['baseline_independent_coverage']
        self.assertEqual(owner_proof[0]['tests'], ['TestAllowed'])
        self.assertEqual(owner_proof[0]['passed'], ['TestAllowed'])
        self.assertRegex(owner_proof[0]['coverprofile_sha256'], r'^[0-9a-f]{64}$')
        self.assertTrue(owner_proof[0]['consumers'][0]['blocks'])

    def test_indirect_replacement_owner_proves_full_body(self):
        # The rewritten old test no longer calls Allowed. A new test reaches
        # it through a helper, so owner discovery must follow the real call
        # chain before accepting its complete positive coverprofile.
        (self.pkg / 'gw_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestAllowed(t *testing.T) { t.Log("rewritten") }\n\n'
            'func allowedByHelper() bool { return Allowed(1) }\n\n'
            'func TestOther(t *testing.T) { if !allowedByHelper() { t.Fatal("denied") } }\n')
        outbox = tempfile.TemporaryDirectory(prefix='critical-gate-out-')
        self.addCleanup(outbox.cleanup)
        out = Path(outbox.name) / 'gate'
        args = argparse.Namespace(root=self.root, base=self.base,
                                  gremlins=gremlins_binary(), output=out)
        self.assertEqual(critical.run(args), 0)
        report = json.loads((out / 'report.json').read_text())
        evidence = report['selector']['evidence'][self.package]
        owner_proof = evidence['baseline_independent_coverage'][0]
        self.assertEqual(owner_proof['tests'], ['TestOther'])
        self.assertEqual(owner_proof['passed'], ['TestOther'])
        self.assertEqual(evidence['rebaselined'],
                         ['TestAllowed → Allowed', 'TestOther → Allowed'])

    def test_skipped_owner_is_not_a_positive_coverage_witness(self):
        # Package init covers Allowed, but the mapped test owner itself skips.
        # Its focused profile must not be treated as an owner pass; complete
        # base/current profiles remain the authority for this ambiguous case.
        (self.pkg / 'gw_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func init() { _ = Allowed(1) }\n\n'
            'func TestAllowed(t *testing.T) { t.Log("rewritten") }\n\n'
            'func TestOther(t *testing.T) { t.Skip("fixture skip"); _ = Allowed(1) }\n')
        from unittest import mock
        real_run = critical_conservative.run_until_deadline
        commands = []

        def observe(argv, root, deadline):
            commands.append(list(argv))
            return real_run(argv, root, deadline)

        outbox = tempfile.TemporaryDirectory(prefix='critical-gate-out-')
        self.addCleanup(outbox.cleanup)
        out = Path(outbox.name) / 'gate'
        args = argparse.Namespace(root=self.root, base=self.base,
                                  gremlins=gremlins_binary(), output=out)
        with mock.patch.object(critical_conservative, 'run_until_deadline',
                               side_effect=observe):
            self.assertEqual(critical.run(args), 0)
        self.assertEqual(len(commands), 3)
        self.assertIn('-run=^(TestOther)$', commands[0])
        report = json.loads((out / 'report.json').read_text())
        evidence = report['selector']['evidence'][self.package]
        self.assertNotIn('baseline_independent_coverage', evidence)

    def test_incomplete_indirect_owner_profile_falls_back_to_full_profiles(self):
        # The changed test stops reaching Allowed; another test reaches it
        # indirectly, but only covers the base-executed branch. A focused
        # profile cannot prove the new branch's absence, so the complete base
        # and current profiles must still decide the verdict.
        production = self.pkg / 'gw.go'
        production.write_text(production.read_text().replace(
            'func Allowed(n int) bool { return n > 0 }',
            'func Allowed(n int) bool { if n > 0 { return true }; return false }'))
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True,
                       capture_output=True)
        subprocess.run(['git', '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'base branch body'], cwd=self.root,
                       check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                            cwd=self.root, text=True).strip()
        (self.pkg / 'gw_test.go').write_text(
            'package auth\n\nimport "testing"\n\n'
            'func TestAllowed(t *testing.T) { t.Log("rewritten") }\n\n'
            'func allowedByHelper() bool { return Allowed(1) }\n\n'
            'func TestOther(t *testing.T) { if !allowedByHelper() { t.Fatal("denied") } }\n')

        from unittest import mock
        real_run = critical_conservative.run_until_deadline
        commands = []

        def observe(argv, root, deadline):
            commands.append(list(argv))
            return real_run(argv, root, deadline)

        outbox = tempfile.TemporaryDirectory(prefix='critical-gate-out-')
        self.addCleanup(outbox.cleanup)
        out = Path(outbox.name) / 'gate'
        args = argparse.Namespace(root=self.root, base=self.base,
                                  gremlins=gremlins_binary(), output=out)
        with mock.patch.object(critical_conservative, 'run_until_deadline',
                               side_effect=observe):
            self.assertEqual(critical.run(args), 0)
        self.assertEqual(len(commands), 3)
        self.assertIn('-json', commands[0])
        self.assertIn('-run=^(TestOther)$', commands[0])
        self.assertNotIn('-run=^(TestOther)$', commands[1])
        self.assertNotIn('-run=^(TestOther)$', commands[2])
        report = json.loads((out / 'report.json').read_text())
        evidence = report['selector']['evidence'][self.package]
        self.assertNotIn('baseline_independent_coverage', evidence)
        self.assertEqual(evidence['rebaselined'],
                         ['TestAllowed → Allowed', 'TestOther → Allowed'])


class CrossPackageConservativeControls(unittest.TestCase):
    """Default conservative selector: cross-package consumers are never silent."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-cross-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        hook = self.root / 'pkg/hook'
        hook.mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.test/critical\n\ngo 1.27.4\n')
        (hook / 'hook.go').write_text(
            'package hook\n\ntype Hook interface {\n\tRun(n int) bool\n}\n\n'
            'func Apply(h Hook, n int) bool { return h.Run(n) }\n')
        user = self.root / 'pkg/hookuser'
        user.mkdir(parents=True)
        (user / 'use.go').write_text(
            'package hookuser\n\nimport "example.test/critical/pkg/hook"\n\n'
            'type adapter struct{}\n\n'
            'func (adapter) Run(n int) bool { return n > 0 }\n\n'
            'func Enabled(n int) bool { return hook.Apply(adapter{}, n) }\n')
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=self.root, check=True, capture_output=True)
        self.base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                            cwd=self.root, text=True).strip()
        self.previous_mode = os.environ.get(critical_scope.MODE_ENV)
        os.environ[critical_scope.MODE_ENV] = critical_scope.CONSERVATIVE
        if self.previous_mode is None:
            self.addCleanup(os.environ.pop, critical_scope.MODE_ENV, None)
        else:
            self.addCleanup(os.environ.__setitem__, critical_scope.MODE_ENV, self.previous_mode)

    def test_changed_interface_widens_importing_package(self):
        (self.root / 'pkg/hook/hook.go').write_text(
            'package hook\n\ntype Hook interface {\n\tRun(n int) bool\n\tName() string\n}\n\n'
            'func Apply(h Hook, n int) bool { return h.Run(n) }\n')
        selected = critical_scope.targets(self.root, self.base,
                                          {'critical_paths': ['pkg/hook/**', 'pkg/hookuser/**']})
        self.assertEqual({fn['name'] for fn in selected['pkg/hookuser']}, {'Enabled', 'Run'})
        evidence = critical_scope.selection_evidence()['pkg/hookuser']
        self.assertTrue(any('cross-package consumer of changed declaration' in reason
                            for reason in evidence['reasons']['*']))

    def test_unchanged_interface_leaves_importer_unselected(self):
        (self.root / 'pkg/hook/hook.go').write_text(
            'package hook\n\ntype Hook interface {\n\tRun(n int) bool\n}\n\n'
            'func Apply(h Hook, n int) bool { return h.Run(n) && n > 0 }\n')
        selected = critical_scope.targets(self.root, self.base,
                                          {'critical_paths': ['pkg/hook/**', 'pkg/hookuser/**']})
        self.assertNotIn('pkg/hookuser', selected)


# Frozen case IDs and expected effects for the selector guarantees below,
# written before any repair. Each control runs the real selector as a
# subprocess of the tree named by G7_SELECTOR_TREE (this worktree by
# default) against a real git fixture repository and the real Go toolchain;
# the system under test is never mocked. Pointing G7_SELECTOR_TREE at the
# pre-repair revision G7_BASELINE_REVISION or at a tree with one guarantee
# reverted must fail exactly the control for that guarantee (three-outcome
# acceptance contract).
G7_SELECTOR_TREE_ENV = 'G7_SELECTOR_TREE'
G7_BASELINE_REVISION = 'c9a6a62'
G7_A1_CONST_SEED = 'G7-A1-CONST-SEED'
G7_A1_PINNED_SEEDED = ['Allowed']
G7_A1_UNIT_DENIAL_EXIT = 1
G7_A2_BLOCK_PRESERVE = 'G7-A2-BLOCK-PRESERVE'
G7_A2_PINNED_REASON = ('lost_block_coverage: pkg/auth: TestAllowed no longer covers '
                       'Allowed, pkg/auth/policy.go:5.3,6.1')
G7_A3_BUDGET_EXHAUSTION = 'G7-A3-BUDGET-EXHAUSTION'
G7_A3_TIMEOUT_REASON = 'unit budget exhausted'
G7_A3_PATCHED_SECONDS = 6
# Each suite alone fits one patched budget; run under one shared pool the
# second suite cannot, which is the property separate budgets would break.
G7_A3_SLOW_SECONDS = 4
G7_A3_WALL_LIMIT = 60
G7_POLICY_CONST = ('package auth\nconst Limit=5\n'
                   'func Allowed(n int) bool { if n > Limit { return false }; return true }\n'
                   'func Other(n int) int { return n+1 }\n')
G7_TESTS_DENIAL = ('package auth\nimport "testing"\n'
                   'func TestAllowed(t *testing.T) { if Allowed(7) '
                   '{ t.Fatal("denial bypass") } }\n'
                   'func FuzzOther(f *testing.F) { f.Add(0); '
                   'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n')
G7_POLICY_BLOCKS = ('package auth\nconst Limit=5\nfunc Allowed(n int) bool {\n'
                    '\tif n > Limit {\n\t\treturn false\n\t}\n\treturn true\n}\n'
                    'func Other(n int) int { return n+1 }\n')
G7_TESTS_BOTH = ('package auth\nimport "testing"\n'
                 'func TestAllowed(t *testing.T) { if Allowed(7) '
                 '{ t.Fatal("denial bypass") }; if !Allowed(0) '
                 '{t.Fatal("false denial")} }\n'
                 'func FuzzOther(f *testing.F) { f.Add(0); '
                 'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n')
G7_TESTS_ALLOW_ONLY = ('package auth\nimport "testing"\n'
                       'func TestAllowed(t *testing.T) { if !Allowed(0) '
                       '{t.Fatal("false denial")} }\n'
                       'func FuzzOther(f *testing.F) { f.Add(0); '
                       'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n')
G7_TESTS_SWAPPED = ('package auth\nimport "testing"\n'
                    'func TestAllowed(t *testing.T) { if !Allowed(0) '
                    '{t.Fatal("false denial")}; if Allowed(7) '
                    '{ t.Fatal("denial bypass") } }\n'
                    'func FuzzOther(f *testing.F) { f.Add(0); '
                    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n')
G7_A2_GOOS_DUP = 'G7-A2-GOOS-DUP'
G7_A2_PARTIAL_MODE = 'G7-A2-PARTIAL-MODE'
G7_A2_PARTIAL_MODE_REASON = ('lost_unit_coverage: pkg/auth: TestAllowed no '
                             'longer exercises Allowed')
G7_LINUX_TESTS_BOTH = ('//go:build linux\n\npackage auth\nimport "testing"\n'
                       'func TestAllowed(t *testing.T) { if Allowed(7) '
                       '{ t.Fatal("denial bypass") }; if !Allowed(0) '
                       '{t.Fatal("false denial")} }\n'
                       'func FuzzOther(f *testing.F) { f.Add(0); '
                       'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n')
G7_LINUX_TESTS_ALLOW_ONLY = ('//go:build linux\n\npackage auth\nimport "testing"\n'
                             'func TestAllowed(t *testing.T) { if !Allowed(0) '
                             '{t.Fatal("false denial")} }\n'
                             'func FuzzOther(f *testing.F) { f.Add(0); '
                             'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n')
G7_LINUX_TESTS_BENIGN = ('//go:build linux\n\npackage auth\nimport "testing"\n'
                         'func TestAllowed(t *testing.T) { if !Allowed(0) '
                         '{t.Fatal("false denial") }; if Allowed(7) '
                         '{ t.Fatal("denial bypass") } }\n'
                         'func FuzzOther(f *testing.F) { f.Add(0); '
                         'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n')
G7_WINDOWS_TESTS = ('//go:build windows\n\npackage auth\nimport "testing"\n'
                    'func TestAllowed(t *testing.T) { if Allowed(9) '
                    '{ t.Fatal("denial bypass") } }\n')
G7_NOT_SPECIAL_TESTS_BOTH = ('//go:build !special\n\npackage auth\n'
                             'import "testing"\n'
                             'func TestAllowed(t *testing.T) { if Allowed(7) '
                             '{ t.Fatal("denial bypass") }; if !Allowed(0) '
                             '{t.Fatal("false denial")} }\n'
                             'func FuzzOther(f *testing.F) { f.Add(0); '
                             'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n')
G7_NOT_SPECIAL_TESTS_DROPPED = ('//go:build !special\n\npackage auth\n'
                                'import "testing"\n'
                                'func TestAllowed(t *testing.T) { Other(1) }\n'
                                'func FuzzOther(f *testing.F) { f.Add(0); '
                                'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n')
G7_SPECIAL_TESTS = ('//go:build special\n\npackage auth\nimport "testing"\n'
                    'func TestOtherSpecial(t *testing.T) { Other(2) }\n')

# G8 frozen case IDs and pinned effects, written before the identity and
# counterpart repairs. Two escape shapes from the stronger-model review: a
# helper name duplicated across mutually exclusive platform files can
# redirect a changed test's baseline closure, and body-identical production
# duplicated across build modes then moved leaves no unique body
# counterpart, which must not silently re-baseline.
G8_HELPER_IDENTITY = 'G8-HELPER-IDENTITY'
G8_COUNTERPART_AMBIGUOUS = 'G8-AMBIGUOUS-COUNTERPART'
G8_CHANGED_TWIN_COVERAGE = 'G8-CHANGED-TWIN-COVERAGE'
G8_A3_NORMAL_UNIT = 'G8-A3-NORMAL-UNIT'
# The dual-mode production files carry a two-line build-tag header, so the
# deny block sits two lines lower than in G7_POLICY_BLOCKS.
G8_DUAL_DENY_SPEC = '7.3,8.1'
G8_COUNTERPART_REASON = ('lost_block_coverage: pkg/auth: TestAllowedDefault no '
                         'longer covers Allowed, pkg/auth/allowed_default_moved.go:' +
                         G8_DUAL_DENY_SPEC)
# Correct sharing leaves ~4s of the pool for the special-mode suite which
# needs ~3s, while a fresh 3s per-mode half-budget cannot fit it: only a
# genuinely shared deadline completes both modes.
G8_A3_PATCHED_SECONDS = 6
G8_A3_DEFAULT_SLOW_MS = 1000
G8_A3_SPECIAL_SLOW_MS = 3000
G8_A3_WALL_LIMIT = 120
# One helper name across mutually exclusive platform files: the Linux twin
# exercises both Allowed branches, the Windows twin only Other. The
# platform test bodies differ, so no (name, hash) twin survives verbatim
# and the relocation guard cannot mask the closure redirect under test.
G8_LINUX_HELPER_BASE = ('//go:build linux\n\npackage auth\nimport "testing"\n'
                        'func TestAllowed(t *testing.T) { assertAllowed(t) }\n'
                        'func assertAllowed(t *testing.T) {\n'
                        '\tt.Helper()\n'
                        '\tif Allowed(7) { t.Fatal("denial bypass") }\n'
                        '\tif !Allowed(0) { t.Fatal("false denial") }\n'
                        '}\n')
# The rewritten test keeps the helper byte-identical: the lost unit is the
# test itself, so only its baseline closure can carry the loss.
G8_LINUX_HELPER_DROP_DENY = ('//go:build linux\n\npackage auth\nimport "testing"\n'
                             'func TestAllowed(t *testing.T) { if !Allowed(0) '
                             '{ t.Fatal("false denial") } }\n'
                             'func assertAllowed(t *testing.T) {\n'
                             '\tt.Helper()\n'
                             '\tif Allowed(7) { t.Fatal("denial bypass") }\n'
                             '\tif !Allowed(0) { t.Fatal("false denial") }\n'
                             '}\n')
G8_LINUX_HELPER_BENIGN = ('//go:build linux\n\npackage auth\nimport "testing"\n'
                          'func TestAllowed(t *testing.T) { assertAllowed(t); Other(1) }\n'
                          'func assertAllowed(t *testing.T) {\n'
                          '\tt.Helper()\n'
                          '\tif Allowed(7) { t.Fatal("denial bypass") }\n'
                          '\tif !Allowed(0) { t.Fatal("false denial") }\n'
                          '}\n')
G8_WINDOWS_HELPER_OTHER = ('//go:build windows\n\npackage auth\nimport "testing"\n'
                           'func TestAllowed(t *testing.T) { assertAllowed(t); Other(2) }\n'
                           'func assertAllowed(t *testing.T) {\n'
                           '\tt.Helper()\n'
                           '\tOther(1)\n'
                           '}\n')
# Hash-identical Allowed bodies in mutually exclusive build-mode files,
# moved to new filenames in the current tree; each mode's own suite keeps
# real coverage, so the only loss is the default mode's dropped deny
# branch and no unique body counterpart exists for either twin.
G8_DEFAULT_PROD = ('//go:build !special\n\npackage auth\nconst Limit=5\n'
                   'func Allowed(n int) bool {\n'
                   '\tif n > Limit {\n\t\treturn false\n\t}\n'
                   '\treturn true\n}\n')
G8_SPECIAL_PROD = G8_DEFAULT_PROD.replace('!special', 'special')
G8_DEFAULT_TESTS = ('//go:build !special\n\npackage auth\n'
                    'import "testing"\n'
                    'func TestAllowedDefault(t *testing.T) {\n'
                    '\tif Allowed(7) { t.Fatal("denial bypass") }\n'
                    '\tif !Allowed(0) { t.Fatal("false denial") }\n'
                    '}\n')
G8_SPECIAL_TESTS = (G8_DEFAULT_TESTS
                    .replace('!special', 'special')
                    .replace('TestAllowedDefault', 'TestAllowedSpecial'))
G8_DEFAULT_TESTS_DROP_DENY = ('//go:build !special\n\npackage auth\n'
                              'import "testing"\n'
                              'func TestAllowedDefault(t *testing.T) {\n'
                              '\tif !Allowed(0) { t.Fatal("false denial") }\n'
                              '}\n')
G8_DEFAULT_TESTS_SWAPPED = ('//go:build !special\n\npackage auth\n'
                            'import "testing"\n'
                            'func TestAllowedDefault(t *testing.T) {\n'
                            '\tif !Allowed(0) { t.Fatal("false denial") }\n'
                            '\tif Allowed(7) { t.Fatal("denial bypass") }\n'
                            '}\n')
# Moved duplicate twins whose bodies CHANGE from baseline: neither
# unique_match nor applicable_counterpart can resolve them (no hash
# equal, no footprint-unique candidate), so every current block must be
# executed in each applicable mode instead of re-baselining on an
# unmappable baseline. The text change keeps line layout and behavior.
G8_CHANGED_DEFAULT_PROD = G8_DEFAULT_PROD.replace('if n > Limit {',
                                                  'if Limit < n {')
G8_CHANGED_SPECIAL_PROD = G8_SPECIAL_PROD.replace('if n > Limit {',
                                                  'if Limit < n {')
# A test name whose every twin disappears must not collapse to the last
# twin's consumers: each removed platform twin binds the production
# coverage it used to carry, directly or through a helper that was
# removed with it.
# The removed-twin fixture keeps Allowed/Other line-identical to
# G7_POLICY_BLOCKS (older controls stay untouched) and adds Unrelated:
# no test ever references it, so a selection that widens instead of
# binding precisely cannot hide behind the exact expected names.
G8_REMOVED_POLICY = G7_POLICY_BLOCKS + 'func Unrelated(n int) int { return n*2 }\n'
G8_REMOVED_LINUX = ('//go:build linux\n\npackage auth\nimport "testing"\n'
                    'func TestRemoved(t *testing.T) {\n'
                    '\tif Allowed(7) { t.Fatal("deny lost") }\n'
                    '\tif !Allowed(0) { t.Fatal("allow lost") }\n'
                    '}\n')
G8_REMOVED_HELPER_LINUX = ('//go:build linux\n\npackage auth\nimport "testing"\n'
                           'func assertRemovedAllowed(t *testing.T) {\n'
                           '\tt.Helper()\n'
                           '\tif Allowed(7) { t.Fatal("deny lost") }\n'
                           '\tif !Allowed(0) { t.Fatal("allow lost") }\n'
                           '}\n'
                           'func TestRemoved(t *testing.T) {\n'
                           '\tt.Helper()\n'
                           '\tassertRemovedAllowed(t)\n'
                           '}\n')
G8_REMOVED_WINDOWS = ('//go:build windows\n\npackage auth\nimport "testing"\n'
                      'func TestRemoved(t *testing.T) {\n'
                      '\tif Other(1) != 2 { t.Fatal("other changed") }\n'
                      '}\n')
G8_REMOVED_OTHER_TESTS = ('package auth\nimport "testing"\n'
                          'func TestOther(t *testing.T) { Other(1) }\n')
G8_REMOVED_REPLACEMENT_TESTS = ('package auth\nimport "testing"\n'
                                'func TestOther(t *testing.T) { Other(1) }\n'
                                'func TestAllowedReplacement(t *testing.T) {\n'
                                '\tif Allowed(7) { t.Fatal("deny lost") }\n'
                                '\tif !Allowed(0) { t.Fatal("allow lost") }\n'
                                '}\n')
# Isolated negative for the executed-coverage leg: identical except the
# deny assertion is gone, so the deny block must drop out of the real
# coverage profile.
G8_REMOVED_REPLACEMENT_NO_DENY = ('package auth\nimport "testing"\n'
                                  'func TestOther(t *testing.T) { Other(1) }\n'
                                  'func TestAllowedReplacement(t *testing.T) {\n'
                                  '\tif !Allowed(0) { t.Fatal("allow lost") }\n'
                                  '}\n')
# No fuzz target here and per-mode slow suites: the unit kind must own
# execution in both modes, each suite fitting its per-mode share alone.
G8_A3_NORMAL_TESTS = ('package auth\nimport "testing"\n'
                      'func TestAllowed(t *testing.T) { if Allowed(7) '
                      '{ t.Fatal("denial bypass") }; if !Allowed(0) '
                      '{t.Fatal("false denial")} }\n')
G8_A3_SLOW_DEFAULT = ('//go:build !special\n\npackage auth\n'
                      'import "testing"\nimport "time"\n'
                      'func TestSlowDefault(t *testing.T) { time.Sleep(' +
                      str(G8_A3_DEFAULT_SLOW_MS) + '*time.Millisecond) }\n')
G8_A3_SLOW_SPECIAL = ('//go:build special\n\npackage auth\n'
                      'import "testing"\nimport "time"\n'
                      'func TestSlowSpecial(t *testing.T) { time.Sleep(' +
                      str(G8_A3_SPECIAL_SLOW_MS) + '*time.Millisecond) }\n')
G8_A3_NORMAL_POLICY = G7_POLICY_BLOCKS.replace('if n > Limit {',
                                               'if Limit < n {')


class G7AuditRepairControls(unittest.TestCase):
    """Permanent real-command qualification controls for the selector guarantees."""

    def write_repo(self, policy, tests):
        """One qualification fixture repository at its baseline commit."""
        temp = tempfile.TemporaryDirectory(prefix='critical-g7-')
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / 'pkg/auth').mkdir(parents=True)
        (root / 'go.mod').write_text('module example.test/critical\n\ngo 1.27.4\n')
        (root / 'pkg/auth/policy.go').write_text(policy)
        (root / 'pkg/auth/policy_test.go').write_text(tests)
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=root, check=True, capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=root, text=True).strip()
        return root, base

    def selector_tree(self):
        """Tree whose selector the controls exercise (this one by default)."""
        return os.environ.get(G7_SELECTOR_TREE_ENV) or \
            str(Path(critical.__file__).resolve().parent)

    def selector_env(self):
        return dict(os.environ, CRITICAL_SCOPE_SELECTOR='conservative',
                    GOWORK='off', GOFLAGS='')

    def run_selector(self, root, base):
        """Real selector run of the tree under test; JSON rows on stdout."""
        code = (
            'import json,sys\n'
            'from pathlib import Path\n'
            'sys.path.insert(0,sys.argv[1])\n'
            'import critical,critical_scope,critical_conservative\n'
            'rows=critical_scope.targets(Path.cwd(),sys.argv[2],'
            "{'critical_paths':['pkg/auth/**'],'build_tags':['']})\n"
            'selected=rows.get("pkg/auth",[])\n'
            'sel=critical_conservative.RUNS.get("pkg/auth")\n'
            'print(json.dumps({"rows":selected,"seed_demands":'
            '[f["name"] for f in critical.seed_functions(selected)],'
            '"widened":(sel[0].widenings or None) if sel else None,'
            '"reasons":(sel[0].reasons or {}) if sel else {},'
            '"lost_baseline":(sel[0].lost_baseline or []) if sel else []}))\n'
        )
        return run_guarded(['python3', '-c', code, self.selector_tree(), base],
                           cwd=root, timeout=180, env=self.selector_env())

    def commit_fixture(self, root, message):
        """Commit the fixture worktree and return the new revision."""
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', message]):
            subprocess.run(['git', *argv], cwd=root, check=True,
                           capture_output=True)
        return subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=root, text=True).strip()

    def write_platform_repo(self, linux_tests, windows_tests):
        """Fixture baseline pairing one test name across two GOOS files."""
        root, _ = self.write_repo(G7_POLICY_BLOCKS, linux_tests)
        (root / 'pkg/auth/policy_test.go').unlink()
        (root / 'pkg/auth/policy_linux_test.go').write_text(linux_tests)
        (root / 'pkg/auth/policy_windows_test.go').write_text(windows_tests)
        return root, self.commit_fixture(root, 'platform pair')

    def write_mode_repo(self):
        """Fixture baseline where the default mode covers Allowed and the
        second configured build mode does not."""
        root, _ = self.write_repo(G7_POLICY_BLOCKS,
                                  G7_NOT_SPECIAL_TESTS_BOTH)
        (root / 'pkg/auth/special_test.go').write_text(G7_SPECIAL_TESTS)
        return root, self.commit_fixture(root, 'mode pair')

    def run_mode_selector(self, root, base):
        """Real selector run under two build modes; JSON rows on stdout."""
        code = (
            'import json,sys\n'
            'from pathlib import Path\n'
            'sys.path.insert(0,sys.argv[1])\n'
            'import critical,critical_scope\n'
            'rows=critical_scope.targets(Path.cwd(),sys.argv[2],'
            "{'critical_paths':['pkg/auth/**'],"
            "'build_tags':['','special']})\n"
            'selected=rows.get("pkg/auth",[])\n'
            'print(json.dumps({"rows":selected,"seed_demands":'
            '[f["name"] for f in critical.seed_functions(selected)]}))\n'
        )
        return run_guarded(['python3', '-c', code, self.selector_tree(), base],
                           cwd=root, timeout=180, env=self.selector_env())

    def test_const_change_demands_seed_for_affected_consumer(self):
        # G7-A1-CONST-SEED: a constant change re-binds its consumer and must
        # carry a fuzz-seed demand for it; the independently specified
        # denial assertion fails after the change, proving real behavior
        # change that seed demands exist to keep checking.
        root, base = self.write_repo(G7_POLICY_CONST, G7_TESTS_DENIAL)
        (root / 'pkg/auth/policy.go').write_text(
            G7_POLICY_CONST.replace('Limit=5', 'Limit=50'))
        proc = self.run_selector(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual([row['name'] for row in result['rows']],
                         G7_A1_PINNED_SEEDED)
        self.assertTrue(all(row['seed'] for row in result['rows']),
                        json.dumps(result['rows']))
        self.assertEqual(result['seed_demands'], G7_A1_PINNED_SEEDED)
        unit = run_guarded(['go', 'test', './pkg/auth', '-run', 'TestAllowed',
                            '-count=1'], cwd=root, timeout=60,
                           env=self.selector_env())
        self.assertEqual(unit.returncode, G7_A1_UNIT_DENIAL_EXIT,
                         unit.stdout + unit.stderr)

    def test_block_loss_after_rewrite_blocks_rebaseline(self):
        # G7-A2-BLOCK-PRESERVE: a rewritten test that still exercises the
        # function but no longer executes a base-covered statement block
        # must block with the pinned block-level reason instead of
        # re-baselining silently on any-block coverage.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G7_TESTS_BOTH)
        (root / 'pkg/auth/policy_test.go').write_text(G7_TESTS_ALLOW_ONLY)
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G7_A2_PINNED_REASON, proc.stdout + proc.stderr)

    def test_baseline_verification_shares_one_unit_budget(self):
        # G7-A3-BUDGET-EXHAUSTION: base and current coverage runs draw down
        # one per-package unit deadline (patched small here). Both suites
        # each fit a fresh budget, so only a genuinely shared pool is
        # exhausted; the over-budget suite is killed as a process group
        # with the pinned reason instead of every verification
        # subprocess starting over with a fresh budget.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G7_TESTS_BOTH)
        (root / 'pkg/auth/slow_test.go').write_text(
            'package auth\nimport "reflect"\nimport "testing"\nimport "time"\n'
            'type runner struct{}\n'
            'func (runner) Run() bool { return Allowed(7) }\n'
            'func TestOther(t *testing.T) {\n'
            '\tv := reflect.ValueOf(runner{}).MethodByName("Run")\n'
            '\tif !v.IsValid() || v.Call(nil)[0].Bool() { t.Fatal("denial bypass") }\n'
            '}\n'
            'func TestSlow(t *testing.T) { time.Sleep(' +
            str(G7_A3_SLOW_SECONDS) + '*time.Second) }\n')
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'slow']):
            subprocess.run(['git', *argv], cwd=root, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=root, text=True).strip()
        # The direct owner now covers only the allowed branch. A separate
        # reflective owner covers denial in the complete suite but is not a
        # focused static owner; its missing block must force full fallback.
        (root / 'pkg/auth/policy_test.go').write_text(G7_TESTS_ALLOW_ONLY)
        code = (
            'import sys\n'
            'from pathlib import Path\n'
            'sys.path.insert(0,sys.argv[1])\n'
            'import critical_conservative\n'
            'critical_conservative.UNIT_VERIFY_SECONDS=' +
            str(G7_A3_PATCHED_SECONDS) + '\n'
            'import critical_scope\n'
            'critical_scope.targets(Path.cwd(),sys.argv[2],'
            "{'critical_paths':['pkg/auth/**'],'build_tags':['']})\n"
            'print("SELECTION-DONE")\n'
        )
        start = time.monotonic()
        proc = run_guarded(['python3', '-c', code, self.selector_tree(), base],
                           cwd=root, timeout=120, env=self.selector_env())
        wall = time.monotonic() - start
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn('SELECTION-DONE', proc.stdout)
        self.assertIn(G7_A3_TIMEOUT_REASON, proc.stdout + proc.stderr)
        self.assertLess(wall, G7_A3_WALL_LIMIT)

    def test_duplicate_platform_name_cannot_hide_lost_block(self):
        # G7-A2-GOOS-DUP: Go permits the same test name in mutually
        # exclusive platform files. Rewriting only the Linux test away
        # from the deny block must block on the pinned lost block; the
        # unchanged Windows duplicate must not spend or replace the
        # Linux baseline and hide the loss.
        root, base = self.write_platform_repo(G7_LINUX_TESTS_BOTH,
                                              G7_WINDOWS_TESTS)
        (root / 'pkg/auth/policy_linux_test.go').write_text(
            G7_LINUX_TESTS_ALLOW_ONLY)
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G7_A2_PINNED_REASON, proc.stdout + proc.stderr)

    def test_duplicate_platform_name_benign_rewrite_rebaselines(self):
        # G7-A2-GOOS-DUP benign half: in a same-named platform pair, a
        # Linux rewrite that still executes every base-executed block
        # re-baselines normally with a seed demand instead of blocking.
        root, base = self.write_platform_repo(G7_LINUX_TESTS_BOTH,
                                              G7_WINDOWS_TESTS)
        (root / 'pkg/auth/policy_linux_test.go').write_text(
            G7_LINUX_TESTS_BENIGN)
        proc = self.run_selector(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual([row['name'] for row in result['rows']], ['Allowed'])
        self.assertTrue(all(row['seed'] for row in result['rows']),
                        json.dumps(result['rows']))
        self.assertEqual(result['seed_demands'], ['Allowed'])

    def test_partial_base_mode_coverage_is_not_vacuous(self):
        # G7-A2-PARTIAL-MODE: vacuous means NO applicable base build
        # mode executed the genuine like-named consumer. When the base
        # default mode covered the consumer and the rewrite drops it,
        # selection must block with lost_unit_coverage even though a
        # second base mode never covered it — a one-mode gap is not a
        # vacuous collision and must never re-baseline or discard the
        # consumer.
        root, base = self.write_mode_repo()
        (root / 'pkg/auth/policy_test.go').write_text(
            G7_NOT_SPECIAL_TESTS_DROPPED)
        proc = self.run_mode_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G7_A2_PARTIAL_MODE_REASON, proc.stdout + proc.stderr)

    def write_helper_platform_repo(self):
        """Fixture baseline with one helper name across two GOOS files."""
        root, _ = self.write_repo(G7_POLICY_BLOCKS, G8_LINUX_HELPER_BASE)
        (root / 'pkg/auth/policy_test.go').unlink()
        (root / 'pkg/auth/policy_linux_test.go').write_text(G8_LINUX_HELPER_BASE)
        (root / 'pkg/auth/policy_windows_test.go').write_text(G8_WINDOWS_HELPER_OTHER)
        return root, self.commit_fixture(root, 'helper platform pair')

    def test_duplicate_helper_name_cannot_redirect_baseline(self):
        # G8-HELPER-IDENTITY: a helper name duplicated across mutually
        # exclusive platform files must not let one twin's closure replace
        # the other's. Rewriting the Linux test away from the deny block
        # while the Windows helper exercises only Other must block on the
        # pinned lost block instead of redirecting the baseline to Other
        # and discarding it as vacuous.
        root, base = self.write_helper_platform_repo()
        (root / 'pkg/auth/policy_linux_test.go').write_text(
            G8_LINUX_HELPER_DROP_DENY)
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G7_A2_PINNED_REASON, proc.stdout + proc.stderr)

    def test_duplicate_helper_name_benign_rewrite_rebaselines(self):
        # G8-HELPER-IDENTITY benign half: a Linux rewrite that still calls
        # the helper re-baselines with both closure consumers selected
        # instead of collapsing the closure to the Windows twin's Other.
        root, base = self.write_helper_platform_repo()
        (root / 'pkg/auth/policy_linux_test.go').write_text(
            G8_LINUX_HELPER_BENIGN)
        proc = self.run_selector(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual({row['name'] for row in result['rows']},
                         {'Allowed', 'Other'})

    def write_dual_mode_repo(self):
        """Fixture baseline with hash-identical Allowed in !special/special files."""
        root, _ = self.write_repo(G8_DEFAULT_PROD, G8_DEFAULT_TESTS)
        (root / 'pkg/auth/policy.go').unlink()
        (root / 'pkg/auth/policy_test.go').unlink()
        (root / 'pkg/auth/allowed_default.go').write_text(G8_DEFAULT_PROD)
        (root / 'pkg/auth/allowed_special.go').write_text(G8_SPECIAL_PROD)
        (root / 'pkg/auth/allowed_default_test.go').write_text(G8_DEFAULT_TESTS)
        (root / 'pkg/auth/allowed_special_test.go').write_text(G8_SPECIAL_TESTS)
        return root, self.commit_fixture(root, 'dual mode pair')

    def test_ambiguous_counterpart_cannot_silently_rebaseline(self):
        # G8-AMBIGUOUS-COUNTERPART: two body-identical Allowed twins moved
        # to new filenames leave no unique body counterpart, which must
        # not silently re-baseline. Dropping the default mode's deny
        # branch must block with the pinned lost block for the moved
        # default-mode file while the special twin keeps its coverage.
        root, base = self.write_dual_mode_repo()
        (root / 'pkg/auth/allowed_default.go').rename(
            root / 'pkg/auth/allowed_default_moved.go')
        (root / 'pkg/auth/allowed_special.go').rename(
            root / 'pkg/auth/allowed_special_moved.go')
        (root / 'pkg/auth/allowed_default_test.go').write_text(
            G8_DEFAULT_TESTS_DROP_DENY)
        proc = self.run_mode_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G8_COUNTERPART_REASON, proc.stdout + proc.stderr)

    def test_ambiguous_counterpart_benign_moves_rebaseline(self):
        # G8-AMBIGUOUS-COUNTERPART benign half: moving both twins while
        # keeping every base-executed block of the rewritten default test
        # re-baselines normally instead of blocking.
        root, base = self.write_dual_mode_repo()
        (root / 'pkg/auth/allowed_default.go').rename(
            root / 'pkg/auth/allowed_default_moved.go')
        (root / 'pkg/auth/allowed_special.go').rename(
            root / 'pkg/auth/allowed_special_moved.go')
        (root / 'pkg/auth/allowed_default_test.go').write_text(
            G8_DEFAULT_TESTS_SWAPPED)
        proc = self.run_mode_selector(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual({row['name'] for row in result['rows']}, {'Allowed'})

    def move_and_change_dual_twin_bodies(self, root):
        """Move both twins and change both bodies, keeping line layout."""
        moved_default = root / 'pkg/auth/allowed_default_moved.go'
        moved_special = root / 'pkg/auth/allowed_special_moved.go'
        (root / 'pkg/auth/allowed_default.go').rename(moved_default)
        (root / 'pkg/auth/allowed_special.go').rename(moved_special)
        moved_default.write_text(G8_CHANGED_DEFAULT_PROD)
        moved_special.write_text(G8_CHANGED_SPECIAL_PROD)

    def test_changed_body_twin_without_counterpart_must_cover_all_blocks(self):
        # G8-CHANGED-TWIN-COVERAGE: moved duplicate twins whose bodies
        # changed leave no resolvable counterpart by hash or mode
        # footprint. The rewrite must still not silently re-baseline:
        # dropping the default mode's deny branch must block on the
        # pinned lost block because the current deny block is unexecuted,
        # while the special twin keeps its full coverage.
        root, base = self.write_dual_mode_repo()
        self.move_and_change_dual_twin_bodies(root)
        (root / 'pkg/auth/allowed_default_test.go').write_text(
            G8_DEFAULT_TESTS_DROP_DENY)
        proc = self.run_mode_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G8_COUNTERPART_REASON, proc.stdout + proc.stderr)

    def test_changed_body_twin_full_coverage_rebaselines(self):
        # G8-CHANGED-TWIN-COVERAGE benign half: with no resolvable
        # counterpart, a rewrite executing every current block in each
        # applicable mode re-baselines normally.
        root, base = self.write_dual_mode_repo()
        self.move_and_change_dual_twin_bodies(root)
        (root / 'pkg/auth/allowed_default_test.go').write_text(
            G8_DEFAULT_TESTS_SWAPPED)
        proc = self.run_mode_selector(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual({row['name'] for row in result['rows']}, {'Allowed'})

    def write_removed_twins_repo(self, linux_tests):
        """Baseline with one test name across two platform files.

        The Linux twin carries the deny/allow branches for Allowed —
        directly or through a helper — while the Windows twin references
        only Other, and a retained TestOther keeps Other selected no
        matter how the removal binds. The policy adds Unrelated (same
        Allowed/Other layout as G7_POLICY_BLOCKS) so widened fallback
        cannot hide behind the exact expected names.
        """
        root, _ = self.write_repo(G8_REMOVED_POLICY, linux_tests)
        (root / 'pkg/auth/policy_test.go').unlink()
        (root / 'pkg/auth/policy_linux_test.go').write_text(linux_tests)
        (root / 'pkg/auth/policy_windows_test.go').write_text(
            G8_REMOVED_WINDOWS)
        (root / 'pkg/auth/other_test.go').write_text(G8_REMOVED_OTHER_TESTS)
        return root, self.commit_fixture(root, 'removed twins pair')

    def assert_removed_twin_selection(self, proc):
        """Pinned selection invariant for every removed-twin case.

        Exact names (never Unrelated — widening cannot hide), a seed
        demand for each selected function, no widening and no lost
        baseline. A seed:false or widen-everything variant fails this
        same invariant instead of merely failing to crash.
        """
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual({row['name'] for row in result['rows']},
                         {'Allowed', 'Other'})
        self.assertTrue(all(row['seed'] for row in result['rows']),
                        json.dumps(result['rows']))
        self.assertEqual(result['seed_demands'], ['Allowed', 'Other'])
        self.assertIsNone(result['widened'], json.dumps(result))
        self.assertEqual(result['lost_baseline'], [], json.dumps(result))

    def test_removed_twin_platform_pair_keeps_every_consumer(self):
        # G8-REMOVED-TWINS: Go permits the same test name in mutually
        # exclusive platform files. Removing BOTH platform files must
        # bind every removed twin's consumers — Allowed from the Linux
        # twin and Other from the Windows twin. Under obligated
        # coverage the bindings queue for verification: with no
        # surviving executor of Allowed the run must fail by name, so a
        # dropped twin cannot pass unnoticed (Other re-baselines
        # through the retained TestOther). assertIn checks the named
        # obligation is present in the loss detail, not the detail's
        # whole content.
        root, base = self.write_removed_twins_repo(G8_REMOVED_LINUX)
        (root / 'pkg/auth/policy_linux_test.go').unlink()
        (root / 'pkg/auth/policy_windows_test.go').unlink()
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(
            'lost_unit_coverage: pkg/auth: TestRemoved no longer '
            'exercises Allowed', proc.stdout + proc.stderr)

    def test_removed_twin_via_helper_keeps_every_consumer(self):
        # G8-REMOVED-TWINS transitive half: the Linux twin reaches
        # Allowed only through a helper that is removed with it, so the
        # binding must use the baseline closure — including every
        # same-named helper twin — rather than the vanished helper's
        # name in the current tree. Both obligations queue and, with no
        # surviving executor, fail by name in deterministic
        # obligation-identity order (test before helper); a closure
        # missing the helper twin would omit its entry from the detail.
        # assertIn checks both named obligations are present, not the
        # detail's whole content.
        root, base = self.write_removed_twins_repo(G8_REMOVED_HELPER_LINUX)
        (root / 'pkg/auth/policy_linux_test.go').unlink()
        (root / 'pkg/auth/policy_windows_test.go').unlink()
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(
            'lost_unit_coverage: pkg/auth: TestRemoved no longer '
            'exercises Allowed; assertRemovedAllowed no longer '
            'exercises Allowed', proc.stdout + proc.stderr)

    def test_removed_twin_replacement_coverage_still_binds(self):
        # G8-REMOVED-TWINS replacement half (selection control): a new
        # test executing every Allowed block is a legitimate coverage
        # replacement, not a loss — no false loss, no widened fallback.
        # Executed coverage is proven separately by the coverprofile
        # control below; this control pins the selection invariant.
        root, base = self.write_removed_twins_repo(G8_REMOVED_LINUX)
        (root / 'pkg/auth/policy_linux_test.go').unlink()
        (root / 'pkg/auth/policy_windows_test.go').unlink()
        (root / 'pkg/auth/other_test.go').write_text(
            G8_REMOVED_REPLACEMENT_TESTS)
        self.assert_removed_twin_selection(self.run_selector(root, base))

    def go_cover(self, root, profile):
        """Actual `go test` coverage profile for the fixture package."""
        return run_guarded(
            ['go', 'test', '-coverprofile=' + profile, './pkg/auth'],
            cwd=root, timeout=120,
            env=dict(os.environ, GOWORK='off', GOFLAGS=''))

    def allowed_span(self, root):
        """First..last line of func Allowed in the fixture policy."""
        text = (root / 'pkg/auth/policy.go').read_text()
        start = None
        for index, line in enumerate(text.splitlines(), 1):
            if line.startswith('func Allowed('):
                start = index
            elif start is not None and line == '}':
                return (start, index)
        self.fail('func Allowed span not found in fixture policy')

    def covered_allowed_blocks(self, root, profile, span):
        """Executed statement blocks of Allowed from a coverprofile.

        Coverprofile paths are import-path qualified (module prefix), so
        the fixture file is matched by suffix, never by an exact path.
        """
        blocks = set()
        for line in (root / profile).read_text().splitlines()[1:]:
            span_text, _, rest = line.partition(' ')
            file_part, _, block = span_text.partition(':')
            if not (file_part == 'pkg/auth/policy.go'
                    or file_part.endswith('/pkg/auth/policy.go')):
                continue
            lo, _, hi = block.partition(',')
            if span[0] <= int(lo.split('.')[0]) <= span[1] and \
                    int(rest.split()[-1]) > 0:
                blocks.add((lo, hi))
        return blocks

    def test_removed_twin_replacement_executes_baseline_blocks(self):
        # G8-REMOVED-TWINS executed-coverage half: selection rows prove
        # binding, not behavior. Real `go test -coverprofile` runs show
        # the replacement executes every Allowed block the removed
        # Linux twin executed — expected coverage comes from the
        # baseline profile, never from the selector — and an isolated
        # replacement without the deny assertion compiles, runs, and
        # loses exactly that block, so this leg cannot pass vacuously.
        root, _ = self.write_removed_twins_repo(G8_REMOVED_LINUX)
        baseline = self.go_cover(root, 'cover-base.out')
        self.assertEqual(baseline.returncode, 0,
                         baseline.stdout + baseline.stderr)
        span = self.allowed_span(root)
        base_blocks = self.covered_allowed_blocks(root, 'cover-base.out',
                                                  span)
        self.assertTrue(base_blocks,
                        'baseline twin covered no Allowed blocks')

        (root / 'pkg/auth/policy_linux_test.go').unlink()
        (root / 'pkg/auth/policy_windows_test.go').unlink()
        (root / 'pkg/auth/other_test.go').write_text(
            G8_REMOVED_REPLACEMENT_TESTS)
        replacement = self.go_cover(root, 'cover-repl.out')
        self.assertEqual(replacement.returncode, 0,
                         replacement.stdout + replacement.stderr)
        repl_blocks = self.covered_allowed_blocks(root, 'cover-repl.out',
                                                  span)
        self.assertEqual(repl_blocks, base_blocks,
                         'replacement lost baseline Allowed blocks')

        # Negative control: identical replacement minus the deny
        # assertion must fail the same invariant, not satisfy it.
        root2, _ = self.write_removed_twins_repo(G8_REMOVED_LINUX)
        (root2 / 'pkg/auth/policy_linux_test.go').unlink()
        (root2 / 'pkg/auth/policy_windows_test.go').unlink()
        (root2 / 'pkg/auth/other_test.go').write_text(
            G8_REMOVED_REPLACEMENT_NO_DENY)
        nodeny = self.go_cover(root2, 'cover-nodeny.out')
        self.assertEqual(nodeny.returncode, 0,
                         nodeny.stdout + nodeny.stderr)
        nodeny_blocks = self.covered_allowed_blocks(root2,
                                                    'cover-nodeny.out',
                                                    span)
        lost = base_blocks - nodeny_blocks
        self.assertTrue(lost, 'no-deny replacement kept every block; '
                              'negative leg is vacuous')

    def test_normal_unit_phase_shares_one_budget_across_modes(self):
        # G8-A3-NORMAL-UNIT: the normal unit phase draws from the same
        # per-package shared deadline in every build mode. With the
        # patched pool the default-mode suite spends ~1s and the
        # special-mode suite (~3s) still fits the shared remainder; a
        # per-mode fresh half-budget cannot, so completing both modes
        # proves the deadline was shared, not reset per mode.
        # The product's named exhaustion guard (remaining() raising
        # "Per-package check budget exhausted") is a pre-launch check
        # that cannot fire here: mode_deadline is always <= the shared
        # remaining time, so an overspending mode dies as an anonymous
        # subprocess timeout first. The harness therefore surfaces the
        # real exhaustion path under a named budget error so the broken
        # variant fails with an explicit, checkable cause instead of an
        # unhandled TimeoutExpired traceback.
        root, _ = self.write_repo(G7_POLICY_BLOCKS, G8_A3_NORMAL_TESTS)
        (root / 'pkg/auth/slow_default_test.go').write_text(G8_A3_SLOW_DEFAULT)
        (root / 'pkg/auth/slow_special_test.go').write_text(G8_A3_SLOW_SPECIAL)
        base = self.commit_fixture(root, 'slow modes')
        (root / 'pkg/auth/policy.go').write_text(G8_A3_NORMAL_POLICY)
        for tags in ('', 'special'):
            argv = ['go', 'test', '-count=1']
            if tags:
                argv.append('-tags=' + tags)
            argv.append('./pkg/auth')
            suite = run_guarded(argv, cwd=root, timeout=60,
                                env=self.selector_env())
            self.assertEqual(suite.returncode, 0, suite.stdout + suite.stderr)
        code = (
            'import sys,tempfile,subprocess\n'
            'from pathlib import Path\n'
            'sys.path.insert(0,sys.argv[1])\n'
            'import critical\n'
            'critical.APPROVED_BUDGET={"unit":' + str(G8_A3_PATCHED_SECONDS) +
            ',"fuzz":420,"mutation":300}\n'
            'config={"critical_paths":["pkg/auth/**"],"build_tags":["","special"],'
            '"budget":{"schema_version":1,"seconds_per_package":{"unit":' +
            str(G8_A3_PATCHED_SECONDS) + ',"fuzz":420,"mutation":300}},'
            '"mutation_qualified_packages":[]}\n'
            'import critical_scope\n'
            'rows=critical_scope.targets(Path.cwd(),sys.argv[2],config)\n'
            'print("SELECTED:"+str(len(rows.get("pkg/auth",[]))))\n'
            'try:\n'
            '    critical.run_package(Path.cwd(),"pkg/auth",rows["pkg/auth"],config,'
            'Path(tempfile.mkdtemp(prefix="g8a3-")),"gremlins-not-used")\n'
            'except subprocess.TimeoutExpired as exhausted:\n'
            '    raise ValueError("unit budget exhausted for pkg/auth: "'
            '+ " ".join(exhausted.cmd) +\n'
            '        " exceeded the shared per-package unit deadline") from exhausted\n'
            'print("UNIT-PHASE-OK")\n'
        )
        start = time.monotonic()
        proc = run_guarded(['python3', '-c', code, self.selector_tree(), base],
                           cwd=root, timeout=150, env=self.selector_env())
        wall = time.monotonic() - start
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('SELECTED:1', proc.stdout)
        self.assertIn('UNIT-PHASE-OK', proc.stdout)
        self.assertLess(wall, G8_A3_WALL_LIMIT)

    def test_run_guarded_timeout_cleans_up_child_processes(self):
        # G8-GUARD-CLEANUP: a timed-out guarded run must terminate its
        # whole process group, not only the direct child — the r1 matrix
        # orphaned go test binaries this exact way. Each leg starts
        # exactly ONE fixture process (the guarded invocation itself, run
        # in a thread so its TimeoutExpired can be asserted), waits on
        # that invocation's readiness pidfile, and then checks the
        # recorded grandchild directly: exception-only is not proof of
        # cleanup. The isolated parent-only broken guard must leave that
        # exact child and be caught by the same no-survivor check before
        # its fixture group is cleaned explicitly. Bounded synthetic
        # shell; no Go involved.
        def fixture(work):
            """Shell whose background grandchild records its own PID.

            `$$` stays the top-level shell inside a subshell, so the
            grandchild is recorded via $BASHPID; its output is redirected
            so a parent-only kill does not block on inherited pipes.
            """
            argv = ['bash', '-c',
                    '( echo "$BASHPID" > "$1/child.pid"; '
                    'exec sleep 30 ) >/dev/null 2>&1 & wait',
                    'bash-guard-fixture', str(work)]
            return argv, work / 'child.pid'

        def readiness(pidfile, limit=10.0):
            deadline = time.monotonic() + limit
            while time.monotonic() < deadline:
                if pidfile.exists() and pidfile.read_text().strip():
                    return int(pidfile.read_text().strip())
                time.sleep(0.05)
            self.fail('guard fixture never became ready: ' + str(pidfile))

        def pid_gone(pid, grace=5.0):
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return True
                time.sleep(0.1)
            return False

        def in_thread(body):
            """Run body once, recording any exception it raises."""
            box = {}

            def run():
                try:
                    body()
                except BaseException as exc:
                    box['exc'] = exc
            thread = threading.Thread(target=run)
            thread.start()
            return thread, box

        def kill_pidgroup(pid):
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

        # Fixed guard: one invocation, its own pidfile, whole group dies.
        work = Path(tempfile.mkdtemp(prefix='g8-guard-'))
        self.addCleanup(shutil.rmtree, work, True)
        argv, pidfile = fixture(work)
        thread, box = in_thread(
            lambda: run_guarded(argv, cwd=work, timeout=0.5, grace=1.0,
                                env=dict(os.environ)))
        child = readiness(pidfile)
        self.addCleanup(kill_pidgroup, child)
        thread.join(30)
        self.assertIsInstance(box.get('exc'), subprocess.TimeoutExpired)
        self.assertTrue(pid_gone(child),
                        'guarded run left recorded child %d alive' % child)

        # Broken parent-only guard: same single-invocation shape; the
        # recorded child must survive and be caught before explicit
        # cleanup of the deliberately broken fixture group.
        broken = Path(tempfile.mkdtemp(prefix='g8-guard-broken-'))
        self.addCleanup(shutil.rmtree, broken, True)
        argv2, pidfile2 = fixture(broken)

        def run_parent_only():
            """Deliberately broken guard: reaps only the direct child."""
            proc = subprocess.Popen(argv2, cwd=str(broken), text=True,
                                    env=dict(os.environ),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    start_new_session=True)
            try:
                proc.communicate(timeout=0.5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise
            return proc.returncode

        thread2, box2 = in_thread(run_parent_only)
        child2 = readiness(pidfile2)
        self.addCleanup(kill_pidgroup, child2)
        thread2.join(30)
        self.assertIsInstance(box2.get('exc'), subprocess.TimeoutExpired)
        self.assertFalse(pid_gone(child2, grace=3.0),
                         'broken guard unexpectedly cleaned the group')
        self.assertFalse(pid_gone(child2, grace=1.0),
                         'no-survivor check failed to catch the orphan')
        kill_pidgroup(child2)
        self.assertTrue(pid_gone(child2))

        # G8-GUARD-ESCALATION: the parent exits to TERM while the
        # grandchild ignores it, so only KILL clears the group. The real
        # guard must prove that exact descendant dead — exception type
        # alone is not evidence — and the isolated escalation-stopper
        # variant that ends cleanup at parent exit must leave it and be
        # caught by the same no-survivor check before explicit cleanup.
        resistant = Path(tempfile.mkdtemp(prefix='g8-guard-resistant-'))
        self.addCleanup(shutil.rmtree, resistant, True)
        argv3 = ['bash', '-c',
                 'trap \'exit 0\' TERM; '
                 '( trap \'\' TERM; echo "$BASHPID" > "$1/child.pid"; '
                 'exec sleep 30 ) >/dev/null 2>&1 & wait',
                 'term-resistant-fixture', str(resistant)]
        pidfile3 = resistant / 'child.pid'
        thread3, box3 = in_thread(
            lambda: run_guarded(argv3, cwd=resistant, timeout=0.5, grace=1.0,
                                env=dict(os.environ)))
        child3 = readiness(pidfile3)
        self.addCleanup(kill_pidgroup, child3)
        thread3.join(30)
        self.assertIsInstance(box3.get('exc'), subprocess.TimeoutExpired)
        self.assertTrue(pid_gone(child3),
                        'guard left TERM-resistant child %d alive' % child3)

        def run_escalation_stopper(argv, cwd, timeout, grace):
            """Deliberately broken guard: cleanup stops at parent exit."""
            proc = subprocess.Popen(argv, cwd=str(cwd), text=True,
                                    env=dict(os.environ),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    start_new_session=True)
            try:
                proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.communicate(timeout=grace)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                raise
            return proc.returncode

        stopper = Path(tempfile.mkdtemp(prefix='g8-guard-stopper-'))
        self.addCleanup(shutil.rmtree, stopper, True)
        argv4 = ['bash', '-c',
                 'trap \'exit 0\' TERM; '
                 '( trap \'\' TERM; echo "$BASHPID" > "$1/child.pid"; '
                 'exec sleep 30 ) >/dev/null 2>&1 & wait',
                 'escalation-stopper-fixture', str(stopper)]
        pidfile4 = stopper / 'child.pid'
        thread4, box4 = in_thread(
            lambda: run_escalation_stopper(argv4, cwd=stopper, timeout=0.5,
                                           grace=1.0))
        child4 = readiness(pidfile4)
        self.addCleanup(kill_pidgroup, child4)
        thread4.join(30)
        self.assertIsInstance(box4.get('exc'), subprocess.TimeoutExpired)
        self.assertFalse(pid_gone(child4, grace=2.0),
                         'escalation stopper unexpectedly killed descendant')
        kill_pidgroup(child4)
        self.assertTrue(pid_gone(child4))

    def test_run_guarded_exception_closes_pipe_descriptors(self):
        # G8-GUARD-PIPES: a retained TimeoutExpired keeps run_guarded's
        # frame — and its Popen pipes — reachable, so garbage collection
        # can never release them. Both descriptors must be closed while
        # the exception and its traceback are still alive in this frame,
        # with no retained descriptor increase; the successful
        # CompletedProcess output contract stays unchanged.
        before = set(os.listdir('/proc/self/fd'))
        work = Path(tempfile.mkdtemp(prefix='g8-guard-pipes-'))
        self.addCleanup(shutil.rmtree, work, True)
        argv = ['bash', '-c', 'trap \'exit 0\' TERM; exec sleep 30',
                'pipe-leak-fixture']
        try:
            run_guarded(argv, cwd=work, timeout=0.5, grace=1.0,
                        env=dict(os.environ))
        except subprocess.TimeoutExpired as caught:
            # The traceback must stay LIVE here: unittest's assertRaises
            # calls traceback.clear_frames and strips the traceback, and
            # the retained frames — run_guarded holding its Popen — are
            # precisely the oracle this control pins.
            proc = None
            tb = caught.__traceback__
            while tb is not None:
                if tb.tb_frame.f_code.co_name == 'run_guarded':
                    proc = tb.tb_frame.f_locals.get('proc')
                tb = tb.tb_next
            self.assertIsNotNone(proc,
                                 'run_guarded frame missing from traceback')
            self.assertIsNotNone(proc.stdout)
            self.assertIsNotNone(proc.stderr)
            self.assertTrue(proc.stdout.closed, 'stdout descriptor leaked')
            self.assertTrue(proc.stderr.closed, 'stderr descriptor leaked')
            self.assertLessEqual(set(os.listdir('/proc/self/fd')), before,
                                 'retained descriptors increased')
        else:
            self.fail('TimeoutExpired not raised')

        done = run_guarded(['bash', '-c', 'echo out; echo err >&2'],
                           cwd=work, timeout=10, env=dict(os.environ))
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, 'out\n')
        self.assertEqual(done.stderr, 'err\n')


# G8F frozen follow-up case material: receiver-distinct method identity
# (analyzer + selection), test-file declaration binding, and deterministic
# pipe closure of the deadline runner. Written before the fixes' final
# acceptance; each control pins the escape the stronger review probed.
G8F_RECEIVER_POLICY = (
    'package auth\nconst Limit=5\n'
    'type Alpha struct{}\ntype Beta struct{}\n'
    'func Allowed(n int) bool { if n > Limit { return false }; return true }\n'
    'func (a Alpha) Check(n int) bool { if n > Limit { return false }; return true }\n'
    'func (b Beta) Check(n int) bool { return n <= Limit }\n'
    'func Other(n int) int { return n+1 }\n'
)
G8F_RECEIVER_TESTS = (
    'package auth\nimport "testing"\n'
    'func TestCheck(t *testing.T) { if !(Alpha{}).Check(1) '
    '{ t.Fatal("alpha false denial") }; if !(Beta{}).Check(1) '
    '{ t.Fatal("beta false denial") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
G8F_RECEIVER_CHANGED = G8F_RECEIVER_POLICY.replace(
    'func (a Alpha) Check(n int) bool { if n > Limit { return false }; '
    'return true }',
    'func (a Alpha) Check(n int) bool { if n >= Limit { return false }; '
    'return true }').replace(
    'func (b Beta) Check(n int) bool { return n <= Limit }',
    'func (b Beta) Check(n int) bool { return n < Limit }')
G8F_RECEIVER_DROP_ALPHA = G8F_RECEIVER_POLICY.replace(
    'func (a Alpha) Check(n int) bool { if n > Limit { return false }; '
    'return true }\n',
    '')
G8F_UNREFERENCED_POLICY = G7_POLICY_BLOCKS + \
    'func Unreferenced(n int) int { return n-1 }\n'
G8F_UNREFERENCED_DROPPED = G7_POLICY_BLOCKS
G8F_DECL_HELPER_TESTS = (
    'package auth\nimport "testing"\n'
    'const markers = 3\n'
    'func checkAllowed(t *testing.T, n int) {\n'
    '\tt.Helper()\n'
    '\tif n < markers && !Allowed(n) { t.Fatal("false denial") }\n'
    '\tif n > markers && Allowed(n) { t.Fatal("denial bypass") }\n'
    '}\n'
    'func TestAllowed(t *testing.T) { checkAllowed(t, 1); checkAllowed(t, 7) }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
G8F_DECL_HELPER_CHANGED = G8F_DECL_HELPER_TESTS.replace(
    'const markers = 3', 'const markers = 5')
G8F_REMOVED_FILE_TESTS = (
    'package auth\nimport "testing"\n'
    'const markers = 3\n'
    'func TestAllowed(t *testing.T) { if Allowed(7) '
    '{ t.Fatal("denial bypass") } }\n'
)
G8F_SURVIVING_FUZZ_TESTS = (
    'package auth\nimport "testing"\n'
    'func TestNarrow(t *testing.T) { if Other(1) < 0 '
    '{ t.Fatal("other") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
# Deny-branch replacement coverage for the removed-file fixture: base
# covered only Allowed's deny branch, so a surviving deny-only test is
# the exact legitimate replacement that lets the removal re-baseline
# while the unbound markers declaration still widens.
G8F_SURVIVING_FUZZ_COVER_TESTS = G8F_SURVIVING_FUZZ_TESTS + \
    'func TestAllowedCover(t *testing.T) { if Allowed(7) ' \
    '{ t.Fatal("deny lost") } }\n'
G8F_BLANK_IMPORT_TESTS = (
    'package auth\nimport "testing"\nimport _ "errors"\n'
    'func TestAllowed(t *testing.T) { if Allowed(7) '
    '{ t.Fatal("denial bypass") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
G8F_IMPORT_BIND_TESTS = (
    'package auth\nimport "testing"\nimport stderrors "errors"\n'
    'func TestAllowed(t *testing.T) { sentinel := stderrors.New("sentinel"); '
    'if !stderrors.Is(sentinel, sentinel) { t.Fatal("sentinel mismatch") }; '
    'if Allowed(7) { t.Fatal("denial bypass") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
G8F_NARROW_TESTS = (
    'package auth\nimport "testing"\n'
    'const narrowMarker = 1\n'
    'func TestNarrow(t *testing.T) { if Other(narrowMarker) < 0 '
    '{ t.Fatal("other") } }\n'
)
G8F_ALIAS_HELPER_TESTS = (
    'package auth\nimport "testing"\nimport errs "errors"\n'
    'func checkErr(t *testing.T) { if errs.New("x") == nil '
    '{ t.Fatal("nil error") } }\n'
    'func TestAllowed(t *testing.T) { checkErr(t); if Allowed(7) '
    '{ t.Fatal("denial bypass") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
G8F_ALIAS_RENAME_TESTS = (
    'package auth\nimport "testing"\n'
    'func checkMsg(t *testing.T) { _ = t }\n'
    'func TestAllowed(t *testing.T) { checkMsg(t); if Allowed(7) '
    '{ t.Fatal("denial bypass") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
G8F_DEFAULT_IMPORT_TESTS = (
    'package auth\nimport "testing"\nimport "errors"\n'
    'func TestAllowed(t *testing.T) { if errors.New("x") == nil '
    '{ t.Fatal("nil error") }; if Allowed(7) '
    '{ t.Fatal("denial bypass") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
G8F_REPATH_BASE_TESTS = (
    'package auth\nimport "testing"\nimport rnd "math/rand"\n'
    'func TestAllowed(t *testing.T) { if rnd.Int() < 0 '
    '{ t.Fatal("negative") }; if Allowed(7) '
    '{ t.Fatal("denial bypass") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
G8F_REPATH_TESTS = (
    'package auth\nimport "testing"\nimport rnd "math/rand/v2"\n'
    'func TestAllowed(t *testing.T) { if rnd.IntN(8) < 0 '
    '{ t.Fatal("negative") }; if Allowed(7) '
    '{ t.Fatal("denial bypass") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)
G8F_TWO_ALIAS_TESTS = (
    'package auth\nimport "testing"\n'
    'import stderrors "errors"\nimport unusedpkg "math"\n'
    'func unusedNumber() float64 { return unusedpkg.Pi }\n'
    'func TestAllowed(t *testing.T) { sentinel := stderrors.New("sentinel"); '
    'if !stderrors.Is(sentinel, sentinel) { t.Fatal("sentinel mismatch") }; '
    'if Allowed(7) { t.Fatal("denial bypass") } }\n'
    'func FuzzOther(f *testing.F) { f.Add(0); '
    'f.Fuzz(func(t *testing.T,n int) { Other(n) }) }\n'
)


# G8R frozen selection-semantics regression material: deny-block loss
# through declaration-only edits or test removal, and consumer swaps
# reachable only through a test-file initializer. The declaration and
# removal fixtures deliberately contain no Fuzz-target name at all — a
# Fuzz name alone is discoverable and would change the no-fuzz-target
# premise of the escape — while the table keeps independent allow and
# deny inputs. Written expectations-first before any repair; each
# control pins the escape the stronger review probed and, per the
# G7_SELECTOR_TREE three-outcome contract, must fail against the
# pre-repair tree while its paired acceptance leg keeps a
# block-preserving change green. Re-baseline records follow
# baseline_record's frozen 'name → fns' format and the block spec below
# is G7-A2's independent pin for the identical policy and allow-only
# coverage shape; fuzz-free fixtures selecting narrow are proven by the
# green G8F narrow control.
G8R_TABLE_TESTS = (
    'package auth\nimport "testing"\n'
    'var inputs = []int{0, 7}\n'
    'func TestTable(t *testing.T) {\n'
    '\tfor _, n := range inputs {\n'
    '\t\tif Allowed(n) != (n <= Limit) {\n'
    '\t\t\tt.Fatal("table mismatch")\n'
    '\t\t}\n'
    '\t}\n'
    '}\n'
)
G8R_TABLE_DROP_DENY = G8R_TABLE_TESTS.replace('[]int{0, 7}', '[]int{0}')
G8R_TABLE_KEPT_BLOCKS = G8R_TABLE_TESTS.replace('[]int{0, 7}', '[]int{3, 7}')
G8R_TABLE_LOST_REASON = ('lost_block_coverage: pkg/auth: TestTable no longer '
                         'covers Allowed, pkg/auth/policy.go:5.3,6.1')
G8R_REMOVED_BASE_TESTS = (
    'package auth\nimport "testing"\n'
    'func TestAllowed(t *testing.T) { if Allowed(7) '
    '{ t.Fatal("denial bypass") }; if !Allowed(0) '
    '{t.Fatal("false denial")} }\n'
)
G8R_SURVIVOR_OTHER_ONLY = (
    'package auth\nimport "testing"\n'
    'func TestNarrow(t *testing.T) { if Other(1) < 0 '
    '{ t.Fatal("other") } }\n'
)
G8R_SURVIVOR_REPLACEMENT = (
    'package auth\nimport "testing"\n'
    'func TestReplacement(t *testing.T) { if Allowed(7) '
    '{ t.Fatal("denial bypass") }; if !Allowed(0) '
    '{t.Fatal("false denial")} }\n'
)
G8R_CALLBACK_POLICY = G7_POLICY_BLOCKS + \
    'func Alternate(n int) bool { return n > Limit }\n'
G8R_CALLBACK_TESTS = (
    'package auth\nimport "testing"\n'
    'var check = Allowed\n'
    'func TestCallback(t *testing.T) { _ = check(0); _ = Other(1) }\n'
)
G8R_CALLBACK_SWAP = G8R_CALLBACK_TESTS.replace('= Allowed', '= Alternate')
G8R_CALLBACK_KEEPS = (
    'func TestKeeps(t *testing.T) { if Allowed(7) '
    '{ t.Fatal("denial bypass") }; if !Allowed(0) '
    '{t.Fatal("false denial")} }\n'
)
G8R_CALLBACK_SWAP_KEPT = G8R_CALLBACK_SWAP + G8R_CALLBACK_KEEPS
# Isolated G8R-CALLBACK-NOEXEC shape: the callback value is retained
# instead of called, so every reference demand survives while Alternate
# is never executed.
G8R_CALLBACK_SWAP_NOEXEC = G8R_CALLBACK_SWAP.replace(
    '_ = check(0)', '_ = check') + G8R_CALLBACK_KEEPS
G8R_CALLBACK_LOST_REASON = ('lost_unit_coverage: pkg/auth: TestCallback no '
                            'longer exercises Allowed')
# Alternate is the one-statement function G7_POLICY_BLOCKS appends at
# policy.go line 10; the independent oracle pins that exact location.
G8R_ALTERNATE_SPEC = ('pkg/auth/policy.go', 10)


class G8FollowupRepairControls(G7AuditRepairControls):
    """Retained qualification controls for the G8 follow-up repairs."""

    def selector_conservative(self):
        """critical_conservative module of the tree under test."""
        path = Path(self.selector_tree()) / 'critical_conservative.py'
        spec = importlib.util.spec_from_file_location(
            'g8f_critical_conservative', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def selector_output(self, root, base):
        """Real selector run parsed as JSON."""
        proc = self.run_selector(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads(proc.stdout)

    def test_receiver_identity_keeps_same_named_methods_distinct(self):
        # G8F-RECV-DISTINCT: two same-named methods on different receivers
        # in one file are two functions. The real analyzer must report
        # their receiver base types, the selection must keep both rows
        # with both seed demands, and the collapse to one (file, name)
        # row must not silently merge them.
        root, base = self.write_repo(G8F_RECEIVER_POLICY, G8F_RECEIVER_TESTS)
        (root / 'pkg/auth/policy.go').write_text(G8F_RECEIVER_CHANGED)
        result = self.selector_output(root, base)
        self.assertEqual(
            [(row['name'], row.get('recv')) for row in result['rows']],
            [('Check', 'Alpha'), ('Check', 'Beta')],
            json.dumps(result['rows']))
        self.assertTrue(all(row['seed'] for row in result['rows']),
                        json.dumps(result['rows']))
        self.assertEqual(result['seed_demands'], ['Check', 'Check'])
        self.assertIsNone(result['widened'])
        self.assertEqual(result['reasons'],
                         {'Alpha.Check': ['changed function: Check'],
                          'Beta.Check': ['changed function: Check']})

    def test_receiver_method_deletion_survives_twin(self):
        # G8F-RECV-DELETE: deleting one of two same-named receiver methods
        # while its twin survives is a removal, not a no-op: a bare-name
        # survivor set cannot hide it, and the widening must name the
        # receiver-distinct label Alpha.Check.
        root, base = self.write_repo(G8F_RECEIVER_POLICY, G8F_RECEIVER_TESTS)
        (root / 'pkg/auth/policy.go').write_text(G8F_RECEIVER_DROP_ALPHA)
        result = self.selector_output(root, base)
        self.assertIsNotNone(result['widened'], json.dumps(result['rows']))
        self.assertTrue(any('removed function still referenced: Alpha.Check'
                            in reason for reason in result['widened']),
                        json.dumps(result['widened']))
        survivors = [(row['name'], row.get('recv'))
                     for row in result['rows'] if row['name'] == 'Check']
        self.assertEqual(survivors, [('Check', 'Beta')],
                         json.dumps(result['rows']))

    def test_unreferenced_production_removal_widens(self):
        # G8F-REMOVED-FUNC: a vanished production function is never proof
        # it went unused. With no bindable reference at all, the selector
        # must keep the obligation explicit instead of silently selecting
        # nothing.
        root, base = self.write_repo(G8F_UNREFERENCED_POLICY,
                                     G7_TESTS_DENIAL)
        (root / 'pkg/auth/policy.go').write_text(G8F_UNREFERENCED_DROPPED)
        result = self.selector_output(root, base)
        self.assertEqual(result['widened'],
                         ['removed production function without visible '
                          'consumers: Unreferenced'],
                         json.dumps(result['widened']))

    def test_test_declaration_change_binds_helper_consumers(self):
        # G8F-TEST-DECL-HELPER: a const value change inside a _test.go file
        # leaves every unit hash identical, so unit pairing sees nothing.
        # The declaration change must still bind the helper-mediated
        # consumers — here the deny-block production Allowed — with the
        # declaration named as the reason, and stay narrow (Other, an
        # unchanged fuzz target's consumer, must stay unselected).
        root, base = self.write_repo(G7_POLICY_BLOCKS, G8F_DECL_HELPER_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G8F_DECL_HELPER_CHANGED)
        result = self.selector_output(root, base)
        self.assertEqual([row['name'] for row in result['rows']], ['Allowed'],
                         json.dumps(result['rows']))
        self.assertTrue(result['rows'][0]['seed'])
        self.assertIsNone(result['widened'])
        self.assertEqual(result['reasons'],
                         {'Allowed': ['test declaration changed: markers → '
                                      'TestAllowed']})

    def test_removed_test_file_declarations_widen(self):
        # G8F-TEST-FILE-REMOVED: deleting a whole test file drops its
        # declarations with it. Removed targets bind their former
        # consumers, but a declaration nothing bindable references must
        # still leave a recorded widening, never a silent gap. The
        # surviving TestAllowedCover executes the base-covered deny
        # branch in both snapshots, so the removal's obligation
        # verifies and the widening stays observable.
        root, _ = self.write_repo(G7_POLICY_BLOCKS, G8F_REMOVED_FILE_TESTS)
        (root / 'pkg/auth/other_test.go').write_text(
            G8F_SURVIVING_FUZZ_COVER_TESTS)
        base = self.commit_fixture(root, 'split tests')
        (root / 'pkg/auth/policy_test.go').unlink()
        result = self.selector_output(root, base)
        self.assertEqual(result['widened'],
                         ['test declaration removed without bindable '
                          'consumer: markers (pkg/auth/policy_test.go)'],
                         json.dumps(result['widened']))

    def test_blank_test_import_change_widens(self):
        # G8F-TEST-BLANK-IMPORT: a blank import added to a test file
        # changes no unit body and no directive, yet pulls package init
        # side effects into the test binary. Mirroring production, the
        # change widens instead of staying invisible.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G7_TESTS_DENIAL)
        (root / 'pkg/auth/policy_test.go').write_text(G8F_BLANK_IMPORT_TESTS)
        result = self.selector_output(root, base)
        self.assertEqual(result['widened'],
                         ['test blank/dot import: pkg/auth/policy_test.go'],
                         json.dumps(result['widened']))

    def test_test_import_change_binds_targets(self):
        # G8F-TEST-IMPORT-BIND: a genuinely used import set change binds
        # only the targets whose closure references the changed alias —
        # not every target in the file. The unchanged fuzz target's
        # consumer Other stays unselected; no widening.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G7_TESTS_DENIAL)
        (root / 'pkg/auth/policy_test.go').write_text(G8F_IMPORT_BIND_TESTS)
        result = self.selector_output(root, base)
        self.assertEqual([row['name'] for row in result['rows']], ['Allowed'],
                         json.dumps(result['rows']))
        self.assertTrue(result['rows'][0]['seed'])
        self.assertIsNone(result['widened'])
        self.assertIn('test declaration imports changed: stderrors → '
                      'TestAllowed', result['reasons']['Allowed'],
                      json.dumps(result['reasons']))
        self.assertNotIn('Other', [row['name'] for row in result['rows']])

    def test_default_import_change_widens(self):
        # G8F-TEST-DEFAULT-IMPORT: a normal default import has no
        # reference-table entry — its declared package name cannot be
        # inferred from the path alone. Adding one to a surviving test
        # file is a named widening, never a silent no-op and never an
        # inferred narrow alias match.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G7_TESTS_DENIAL)
        (root / 'pkg/auth/policy_test.go').write_text(G8F_DEFAULT_IMPORT_TESTS)
        result = self.selector_output(root, base)
        self.assertEqual(result['widened'],
                         ['test default import changed: '
                          'pkg/auth/policy_test.go'],
                         json.dumps(result['widened']))

    def test_repathed_explicit_import_alias_binds(self):
        # G8F-TEST-IMPORT-REPATH: the explicit alias stays the same while
        # the import declaration's path — and so its hash and meaning —
        # changes. The alias counts as changed: the closure referencing
        # it binds Allowed narrowly with its own reason and no widening,
        # and Other is not selected by any file-wide import binding.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G8F_REPATH_BASE_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G8F_REPATH_TESTS)
        result = self.selector_output(root, base)
        self.assertEqual([row['name'] for row in result['rows']], ['Allowed'],
                         json.dumps(result['rows']))
        self.assertTrue(result['rows'][0]['seed'])
        self.assertIsNone(result['widened'])
        self.assertIn('test declaration imports changed: rnd → TestAllowed',
                      result['reasons']['Allowed'],
                      json.dumps(result['reasons']))

    def test_removed_import_alias_changed_target_stays_narrow(self):
        # G8F-TEST-IMPORT-DROP-CHANGED: a removed alias with only baseline
        # references claims a carry by the unit pass. The changed target's
        # own binding must really exist — reason 'changed test target:
        # TestAllowed' and a narrow seed row for Allowed — or the carry
        # claim is a silent hole; Other stays unselected, no widening.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G8F_IMPORT_BIND_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G7_TESTS_DENIAL)
        result = self.selector_output(root, base)
        self.assertEqual([row['name'] for row in result['rows']], ['Allowed'],
                         json.dumps(result['rows']))
        self.assertTrue(result['rows'][0]['seed'])
        self.assertIsNone(result['widened'])
        self.assertIn('changed test target: TestAllowed',
                      result['reasons']['Allowed'],
                      json.dumps(result['reasons']))

    def test_removed_import_alias_renamed_helper_widens_named(self):
        # G8F-TEST-IMPORT-DROP-RENAMED: the removed alias's only baseline
        # referencing unit is a helper renamed away. The carry claim is
        # the removed-target pass: it must widen naming checkErr, never
        # silently accept the loss.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G8F_ALIAS_HELPER_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G8F_ALIAS_RENAME_TESTS)
        result = self.selector_output(root, base)
        self.assertEqual(result['widened'],
                         ['removed test target without bindable consumer: '
                          'checkErr'],
                         json.dumps(result['widened']))

    def test_removed_import_alias_removed_helper_widens_named(self):
        # G8F-TEST-IMPORT-DROP-REMOVED: same carry claim when the helper is
        # deleted outright: the removed-target pass names checkErr in a
        # widening instead of letting the baseline reference prove safety.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G8F_ALIAS_HELPER_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G7_TESTS_DENIAL)
        result = self.selector_output(root, base)
        self.assertEqual(result['widened'],
                         ['removed test target without bindable consumer: '
                          'checkErr'],
                         json.dumps(result['widened']))

    def test_unrelated_test_declaration_addition_stays_narrow(self):
        # G8F-TEST-DECL-NARROW: a new test file with its own declaration
        # binds only its own consumers. The deny-block Allowed stays
        # unselected: declaration binding must not select everything on
        # every test edit.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G7_TESTS_DENIAL)
        (root / 'pkg/auth/narrow_test.go').write_text(G8F_NARROW_TESTS)
        result = self.selector_output(root, base)
        self.assertEqual([row['name'] for row in result['rows']], ['Other'],
                         json.dumps(result['rows']))
        self.assertIsNone(result['widened'])

    def test_two_changed_aliases_widen_only_the_unbound_one(self):
        # G8F-TEST-IMPORT-TWO-ALIASES: two explicit import aliases change
        # in one surviving file. The alias TestAllowed references binds
        # Allowed narrowly with its own reason; the alias only a
        # caller-less helper references — no target's closure reaches it,
        # and it touches no production — gets its own named widening. One
        # alias's success must never suppress the other's obligation,
        # which the earlier aggregate bound-or shape missed. The recorded
        # widening, not the binding, is what carries the remaining rows
        # into scope.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G7_TESTS_DENIAL)
        (root / 'pkg/auth/policy_test.go').write_text(G8F_TWO_ALIAS_TESTS)
        result = self.selector_output(root, base)
        self.assertEqual(result['widened'],
                         ['test import changed without bindable consumer: '
                          'unusedpkg (pkg/auth/policy_test.go)'],
                         json.dumps(result['widened']))
        names = [row['name'] for row in result['rows']]
        self.assertIn('Allowed', names, json.dumps(result['rows']))
        self.assertTrue(result['rows'][names.index('Allowed')]['seed'])
        self.assertIn('test declaration imports changed: stderrors → '
                      'TestAllowed', result['reasons']['Allowed'],
                      json.dumps(result['reasons']))

    def test_run_until_deadline_closes_pipes_on_every_path(self):
        # G8F-DEADLINE-PIPES: run_until_deadline must close its stdout
        # pipe deterministically on the ordinary and the timeout path,
        # with the child reaped and no retained descriptor growth while
        # the Popen object is still deliberately alive. The original
        # timeout path left the pipe open on the retained object.
        conservative = self.selector_conservative()
        work = Path(tempfile.mkdtemp(prefix='g8f-pipes-'))
        self.addCleanup(shutil.rmtree, work, True)
        recorded = []
        real_popen = subprocess.Popen

        def recording(argv, deadline):
            """One real run under a recording Popen; returns (result, proc)."""
            def popen(*args, **kwargs):
                proc = real_popen(*args, **kwargs)
                recorded.append(proc)
                return proc
            conservative.subprocess.Popen = popen
            try:
                return conservative.run_until_deadline(argv, work, deadline), \
                    recorded[-1]
            finally:
                conservative.subprocess.Popen = real_popen

        before = set(os.listdir('/proc/self/fd'))
        (code, out), proc = recording(['bash', '-c', 'echo ready'],
                                      time.monotonic() + 10)
        self.assertEqual((code, out), (0, 'ready\n'))
        self.assertIsNotNone(proc.poll(), 'ordinary path left child unreaped')
        self.assertTrue(proc.stdout.closed, 'ordinary path leaked stdout')
        self.assertLessEqual(set(os.listdir('/proc/self/fd')), before,
                             'ordinary path grew retained descriptors')

        before = set(os.listdir('/proc/self/fd'))
        (code, out), proc = recording(
            ['bash', '-c', 'echo partial; exec sleep 30'],
            time.monotonic() + 0.5)
        self.assertEqual((code, out), (None, ''))
        self.assertIsNotNone(proc.poll(), 'timeout path left child unreaped')
        self.assertIsNotNone(proc.stdout)
        self.assertTrue(proc.stdout.closed, 'timeout path leaked stdout')
        self.assertLessEqual(set(os.listdir('/proc/self/fd')), before,
                             'retained Popen grew descriptors')


class G8RSelectionRegressionControls(G8FollowupRepairControls):
    """Expectations-first controls for the G8R selection-semantics gaps.

    Each control runs the real selector pipeline (targets → binding →
    verify_lost_baseline) against real git fixture repositories and the
    real Go toolchain, inheriting the G7_SELECTOR_TREE three-outcome
    contract: against the pre-repair tree exactly these controls fail.
    The declaration/removal fixtures carry no Fuzz-target name at all,
    because the pinned escape is the no-fuzz-target shape.
    """

    def run_selector_records(self, root, base):
        """Real selector run that also reports recorded re-baselines.

        Identical pipeline to run_selector; additionally surfaces the
        package's `rebaselined` evidence, which verify_package_baseline
        records only when a queued baseline actually ran and held. An
        acceptance leg can then prove the gate executed instead of
        silently skipping, which a bare exit zero cannot show.

        A transparent observer wraps only the run_until_deadline seam:
        it calls the original with the same deadline and, once a real
        `go test -coverprofile` completes, reads those exact profile
        bytes immediately — before covered_functions returns and its
        TemporaryDirectory cleans up. Each record keeps origin (base
        tree whenever the run root differs from the fixture root),
        root, package, mode, the full argv, the direct rc, the raw
        profile text and its SHA256. The original seam is restored in
        finally; coverage_blocks and every selector decision are
        untouched, and the bytes are read, never written.
        """
        code = (
            'import hashlib,json,sys\n'
            'from pathlib import Path\n'
            'sys.path.insert(0,sys.argv[1])\n'
            'import critical,critical_scope,critical_conservative as cc\n'
            'observed=[]\n'
            'real_run=cc.run_until_deadline\n'
            'def observed_run(argv,root,deadline):\n'
            '    rc,out=real_run(argv,root,deadline)\n'
            '    if not any(part.startswith("-coverprofile=") '
            'for part in argv):\n'
            '        return rc,out\n'
            '    record={"origin":"base tree" if Path(root)!=Path.cwd() '
            'else "current tree",\n'
            '            "root":str(root),\n'
            '            "package":argv[-1].removeprefix("./"),\n'
            '            "mode":next((part.removeprefix("-tags=") '
            'for part in argv\n'
            '                        if part.startswith("-tags=")),""),\n'
            '            "argv":[str(part) for part in argv],"rc":rc}\n'
            '    if rc==0:\n'
            '        path=Path(next(part.removeprefix("-coverprofile=") '
            'for part in argv\n'
            '                        if part.startswith("-coverprofile=")))\n'
            '        data=path.read_bytes()\n'
            '        record["profile"]=data.decode()\n'
            '        record["profile_sha256"]='
            'hashlib.sha256(data).hexdigest()\n'
            '    observed.append(record)\n'
            '    return rc,out\n'
            'cc.run_until_deadline=observed_run\n'
            'try:\n'
            '    rows=critical_scope.targets(Path.cwd(),sys.argv[2],'
            "{'critical_paths':['pkg/auth/**'],'build_tags':['']})\n"
            '    evidence=cc.EVIDENCE["packages"].get("pkg/auth") or {}\n'
            '    sel=cc.RUNS.get("pkg/auth")\n'
            '    print(json.dumps({"rows":rows.get("pkg/auth",[]),'
            '"rebaselined":evidence.get("rebaselined",[]),'
            '"widened":(sel[0].widenings or None) if sel else None,'
            '"observed":observed}))\n'
            'finally:\n'
            '    cc.run_until_deadline=real_run\n'
        )
        return run_guarded(['python3', '-c', code, self.selector_tree(), base],
                           cwd=root, timeout=180, env=self.selector_env())

    def assert_rebaselined(self, root, base, expected):
        """Acceptance leg: the gate ran, held, and recorded its proof."""
        proc = self.run_selector_records(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result['rebaselined'], expected,
                         json.dumps(result, sort_keys=True))

    def observed_profile(self, result, origin):
        """The one completed raw coverage record of one tree from this run.

        A record qualifies only with a successful real `go test
        -coverprofile ./pkg/auth` command whose recorded SHA256 matches
        the retained bytes; missing profiles, failed or uncompleted
        commands fail the control instead of passing vacuously.
        """
        records = [record for record in result['observed']
                   if record.get('origin') == origin
                   and record.get('package') == 'pkg/auth'
                   and 'profile' in record]
        self.assertEqual(
            len(records), 1,
            'expected one completed ' + origin + ' pkg/auth coverage run: ' +
            json.dumps(result.get('observed', []), sort_keys=True))
        record = records[0]
        self.assertEqual(record['rc'], 0, json.dumps(record, sort_keys=True))
        self.assertEqual(record['argv'][:2], ['go', 'test'],
                         json.dumps(record, sort_keys=True))
        self.assertTrue(any(part.startswith('-coverprofile=')
                            for part in record['argv']),
                        json.dumps(record, sort_keys=True))
        self.assertEqual(record['argv'][-1], './pkg/auth',
                         json.dumps(record, sort_keys=True))
        self.assertEqual(
            record['profile_sha256'],
            hashlib.sha256(record['profile'].encode()).hexdigest(),
            json.dumps(record, sort_keys=True))
        return record

    def block_execution(self, profile, spec):
        """Execution count of the single cover block starting at spec's line.

        Parses go cover text independently; the selector and its helpers
        never derive this expectation.
        """
        suffix, line = spec
        counts = []
        for entry in profile.splitlines()[1:]:
            match = re.fullmatch(r'(.+):(\d+)\.\d+,\d+\.\d+ \d+ (\d+)', entry)
            if match is None:
                raise AssertionError('malformed cover profile line: ' + entry)
            if match[1].endswith(suffix) and int(match[2]) == line:
                counts.append(int(match[3]))
        self.assertEqual(len(counts), 1,
                         'expected one block at ' + suffix + ':' + str(line) +
                         ', counts=' + str(counts))
        return counts[0]

    def assert_alternate_newly_executed(self, result):
        """Independent current-coverage oracle for the callback fixture.

        Alternate must be unexecuted in the selector's own base profile
        and executed in its current profile from the SAME run; demands
        (rows, seeds, the record) never substitute. Bounded scope: this
        proves Alternate ran in this qualification run only; it does not
        prove the installed selector enforces current coverage for every
        newly bound consumer.
        """
        base = self.block_execution(
            self.observed_profile(result, 'base tree')['profile'],
            G8R_ALTERNATE_SPEC)
        current = self.block_execution(
            self.observed_profile(result, 'current tree')['profile'],
            G8R_ALTERNATE_SPEC)
        self.assertEqual(base, 0,
                         'Alternate already executed at base: count=' +
                         str(base))
        self.assertGreater(current, 0,
                           'Alternate not executed by the selector coverage '
                           'phase: count=' + str(current))

    def assert_callback_swap_demands(self, result, expected_rebaselined):
        """Demand contract of the callback swap legs.

        Exactly the three production identities are selected, each with
        a seed demand, no widening occurred, and `rebaselined` equals
        the expected list exactly. The kept leg verifies one obligation;
        the noexec leg edits both the initializer and the callback body,
        so it verifies two distinct obligations whose rendered pair
        coincides — a fact of this fixture, not a general multiplicity
        rule. Demands, never execution proof.
        """
        self.assertEqual(result['rebaselined'], expected_rebaselined,
                         json.dumps(result, sort_keys=True))
        self.assertEqual(sorted(row['name'] for row in result['rows']),
                         ['Allowed', 'Alternate', 'Other'],
                         json.dumps(result, sort_keys=True))
        self.assertTrue(all(row['seed'] for row in result['rows']),
                        json.dumps(result, sort_keys=True))
        self.assertIsNone(result['widened'],
                          json.dumps(result, sort_keys=True))

    def write_removed_replacement_repo(self, survivors):
        """Baseline suite split so policy_test.go can vanish under
        surviving fuzz-free company of the given shape."""
        root, _ = self.write_repo(G7_POLICY_BLOCKS, G8R_REMOVED_BASE_TESTS)
        (root / 'pkg/auth/other_test.go').write_text(survivors)
        base = self.commit_fixture(root, 'split tests')
        (root / 'pkg/auth/policy_test.go').unlink()
        return root, base

    def test_table_input_change_must_preserve_baseline_blocks(self):
        # G8R-DECL-BLOCK: shrinking a table declaration drops the deny
        # branches no rewritten test body accompanies — every unit hash
        # is identical and no fuzz target exists, so unit pairing and
        # seed fallback both see nothing. The baseline block obligation
        # must still verify and block with the pinned block reason
        # (same policy and allow-only shape as G7-A2) instead of
        # re-baselining silently on the surviving allow block.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G8R_TABLE_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G8R_TABLE_DROP_DENY)
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G8R_TABLE_LOST_REASON, proc.stdout + proc.stderr)

    def test_table_input_change_kept_values_rebaseline(self):
        # G8R-DECL-BLOCK acceptance leg: a replacement input set that
        # still executes every baseline block is a legitimate
        # re-baseline, not a loss — and the recorded re-baseline proves
        # the gate ran rather than skipped, which a bare exit zero
        # cannot show.
        root, base = self.write_repo(G7_POLICY_BLOCKS, G8R_TABLE_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G8R_TABLE_KEPT_BLOCKS)
        self.assert_rebaselined(root, base, ['TestTable → Allowed'])

    def test_removed_test_file_coverage_loss_blocks(self):
        # G8R-DECL-BLOCK removal half: deleting the test file that
        # carried both Allowed blocks must verify the survivors really
        # replaced that coverage. With no fuzz target anywhere and
        # survivors exercising Other only, the removal blocks with the
        # pinned unit reason instead of selecting former consumers and
        # stopping there.
        root, base = self.write_removed_replacement_repo(
            G8R_SURVIVOR_OTHER_ONLY)
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G7_A2_PARTIAL_MODE_REASON, proc.stdout + proc.stderr)

    def test_removed_test_file_block_preserving_replacement_rebaselines(self):
        # G8R-DECL-BLOCK removal acceptance leg: a replacement test
        # executing every baseline block is a legitimate re-baseline of
        # the removed test's obligations — no false loss, and the record
        # proves the verification actually ran.
        root, base = self.write_removed_replacement_repo(
            G8R_SURVIVOR_REPLACEMENT)
        self.assert_rebaselined(root, base, ['TestAllowed → Allowed'])

    def test_callback_initializer_swap_blocks_lost_coverage(self):
        # G8R-CALLBACK-INIT: swapping a test-file initializer
        # (var check = Allowed → Alternate) changes no test body, so the
        # body-visible Other cannot hide the loss: the selection must
        # bind both initializer-reached consumers — blocking on the
        # no-longer-exercised Allowed with the pinned reason — or widen
        # explicitly. Silent narrow success binding only Other (or only
        # one initializer side) is the escape this control forbids.
        root, base = self.write_repo(G8R_CALLBACK_POLICY, G8R_CALLBACK_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G8R_CALLBACK_SWAP)
        proc = self.run_selector(root, base)
        if proc.returncode == 0:
            result = json.loads(proc.stdout)
            bound = {row['name'] for row in result['rows']}
            self.assertTrue(
                result['widened'] or bound >= {'Allowed', 'Alternate'},
                json.dumps(result))
        else:
            self.assertIn(G8R_CALLBACK_LOST_REASON,
                          proc.stdout + proc.stderr)

    def test_callback_initializer_swap_with_kept_coverage_rebaselines(self):
        # G8R-CALLBACK-INIT acceptance leg: TestKeeps keeps every baseline
        # block of the initializer-reached consumers, so the swap
        # legitimately re-baselines as the baseline-executed pair
        # Allowed, Other — Alternate stays a demand outside that record
        # because its like-name base counterpart was never executed. Its
        # current execution is proven from this same run's retained raw
        # profiles, not from selection, seeds or the record. Fuzz N/A:
        # no fuzz target exists in this fixture; the unit suite is not
        # a substitute for the independent coverage assertion.
        root, base = self.write_repo(G8R_CALLBACK_POLICY, G8R_CALLBACK_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G8R_CALLBACK_SWAP_KEPT)
        proc = self.run_selector_records(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assert_callback_swap_demands(
            result, ['TestCallback → Allowed, Other'])
        self.assert_alternate_newly_executed(result)

    def test_callback_initializer_swap_no_execution_rejected(self):
        # G8R-CALLBACK-NOEXEC isolated negative: `_ = check` keeps every
        # demand — Alternate still selected and seeded, Allowed still
        # covered by TestKeeps, the pair still re-baselined, no widening
        # — while Alternate is never executed. The selector-level
        # assertions prove the fixture compiled and selected, so the
        # rejection below is the missing current-coverage demand itself,
        # not a compilation or setup failure: the independent oracle
        # must fail on the raw zero count instead of accepting the
        # narrow silent pass.
        root, base = self.write_repo(G8R_CALLBACK_POLICY, G8R_CALLBACK_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(
            G8R_CALLBACK_SWAP_NOEXEC)
        proc = self.run_selector_records(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assert_callback_swap_demands(
            result, ['TestCallback → Allowed, Other',
                     'TestCallback → Allowed, Other'])
        current = self.block_execution(
            self.observed_profile(result, 'current tree')['profile'],
            G8R_ALTERNATE_SPEC)
        self.assertEqual(current, 0,
                         'noexec fixture must leave Alternate unexecuted')
        with self.assertRaises(AssertionError) as caught:
            self.assert_alternate_newly_executed(result)
        self.assertIn('Alternate not executed', str(caught.exception))

    def run_budget_scenario(self, unit_seconds, packages):
        """G8R-MULTI-PACKAGE-BUDGET controlled-clock budget scenario.

        Hand-fixed durations on a fake clock (setup 10s per package,
        20s per coverage run, unit via unit_seconds, fuzz 400s, mutation
        290s); only the subprocess boundaries archive, coverage runs,
        active_functions and run_mode are replaced, and the real
        verify_package_baseline and run_package drive the sequence.
        Returns the child's JSON result: outcome plus the exact
        boundary-event ledger with recorded unit remainders.
        """
        code = r'''
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import critical, critical_conservative as cc

clock = {"now": 1000.0, "events": []}

def advance(seconds, boundary, package, remaining=None):
    event = {"package": package, "boundary": boundary, "seconds": seconds}
    if remaining is not None:
        event["remaining"] = remaining
    clock["events"].append(event)
    clock["now"] += seconds

def row(package):
    return {"file": package + "/a.go", "name": "Allowed", "recv": "",
            "hash": "same-body", "start": 1, "end": 3}

def side(package):
    s = object.__new__(cc.Side)
    s.root = Path.cwd()
    s.files = {package + "/a.go": {"units": [row(package)]}}
    s.production = [package + "/a.go"]
    s.tests = []
    s.dispatch_names = set()
    s.dispatch_unresolved = False
    return s

def fake_archive(_root, _base, _dest):
    advance(10, "setup", next(setups))

def fake_coverage(argv, _root, deadline):
    package = argv[-1].removeprefix("./")
    critical.remaining(deadline)
    profile = next(Path(a.removeprefix("-coverprofile=")) for a in argv
                   if a.startswith("-coverprofile="))
    profile.write_text("mode: set\n" + package + "/a.go:1.1,3.1 1 1\n")
    advance(20, "coverage", package)
    critical.remaining(deadline)
    return 0, ""

def fake_run_mode(kind, _root, package, _functions, _tags, _out, deadline,
                  _gremlins, _qualified):
    left = critical.remaining(deadline)
    seconds = {"unit": float(sys.argv[2]), "fuzz": 400.0,
               "mutation": 290.0}[kind]
    advance(seconds, kind, package, remaining=left)
    critical.remaining(deadline)
    return {"status": "passed"}

critical.time.monotonic = lambda: clock["now"]
cc.time.monotonic = lambda: clock["now"]
cc.source.archive = fake_archive
cc.run_until_deadline = fake_coverage
critical.active_functions = (lambda _root, _package, functions, _tags,
                             _out, _deadline: functions)
critical.run_mode = fake_run_mode
cc.reset_selection()
packages = json.loads(sys.argv[4])
for package in packages:
    selection = cc.Selection(package)
    selection.note_lost_baseline("TestChanged", [row(package)])
    cc.RUNS[package] = (selection, side(package), side(package))
setups = iter(sorted(cc.RUNS))
config = {"budget": {"schema_version": 1, "seconds_per_package":
                     {"unit": 300, "fuzz": 420, "mutation": 300}},
          "build_tags": [""], "mutation_qualified_packages": []}
cc.verify_lost_baseline(Path.cwd(), sys.argv[3], config)
out = Path(tempfile.mkdtemp(prefix="g8r-budget-"))
result = {"outcome": "completed", "events": clock["events"]}
try:
    for package in packages:
        critical.run_package(Path.cwd(), package, [row(package)], config,
                             out / package, "unused-gremlins")
except TimeoutError as exc:
    result["outcome"] = "budget_exhausted"
    result["error"] = str(exc)
print(json.dumps(result))
'''
        root, base = self.write_repo(G7_POLICY_BLOCKS, G7_TESTS_BOTH)
        proc = run_guarded(['python3', '-c', code, self.selector_tree(),
                            str(unit_seconds), base, json.dumps(packages)],
                           cwd=root, timeout=120, env=self.selector_env())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads(proc.stdout)

    def test_multi_package_budget_ignores_unrelated_work_and_charges_setup(self):
        """G8R-MULTI-PACKAGE-BUDGET: unrelated work is free; setup is not.

        A heavy pkg/a must not spend pkg/b's banked unit remainder, while
        pkg/b's own setup and baseline coverage are charged to its one
        300s unit budget: hand-fixed 10s setup + 2x20s coverage leave 250s
        at pkg/b's unit boundary. B runs all three kinds, and each kind
        is bounded by its own approved budget, never mixed.
        """
        result = self.run_budget_scenario(20, ['pkg/a', 'pkg/b'])
        self.assertEqual(result['outcome'], 'completed', result)
        expected = [('pkg/a', 'setup', 10), ('pkg/a', 'coverage', 20),
                    ('pkg/a', 'coverage', 20), ('pkg/b', 'setup', 10),
                    ('pkg/b', 'coverage', 20), ('pkg/b', 'coverage', 20),
                    ('pkg/a', 'unit', 20), ('pkg/a', 'fuzz', 400),
                    ('pkg/a', 'mutation', 290), ('pkg/b', 'unit', 20),
                    ('pkg/b', 'fuzz', 400), ('pkg/b', 'mutation', 290)]
        actual = [(e['package'], e['boundary'], e['seconds'])
                  for e in result['events']]
        self.assertEqual(actual, expected, result)
        for package in ('pkg/a', 'pkg/b'):
            event = next(
                (e for e in result['events'] if e['package'] == package
                 and e['boundary'] == 'unit'), None)
            self.assertIsNotNone(event, result)
            # Own setup + verify consume at most 50 of the 300s unit
            # budget: floor = 300 - 10 - 2*20. Unrelated A work must not
            # push a package's unit remainder below that floor.
            self.assertGreaterEqual(event['remaining'], 250, result)
        b_events = [e for e in result['events'] if e['package'] == 'pkg/b']
        b_unit_bucket = sum(e['seconds'] for e in b_events
                            if e['boundary'] in ('setup', 'coverage', 'unit'))
        self.assertLessEqual(b_unit_bucket, 300)  # 10+20+20+20 = 70
        self.assertLessEqual(
            sum(e['seconds'] for e in b_events if e['boundary'] == 'fuzz'),
            420)
        self.assertLessEqual(
            sum(e['seconds'] for e in b_events
                if e['boundary'] == 'mutation'), 300)

    def test_unit_budget_caps_b_owned_total_including_setup(self):
        """G8R-MULTI-PACKAGE-BUDGET: a B-owned overrun exhausts, setup included.

        Hand-fixed: setup 10 + coverage 2x20 leave 250s, so a 255s unit
        run makes the B-owned unit-bucket total 305 > 300 and must end in
        the pinned exhaustion error, never a pass. A scheduler that omits
        setup charging (295 charged) or resets per subprocess would pass
        it.
        """
        result = self.run_budget_scenario(255, ['pkg/b'])
        self.assertEqual(result['outcome'], 'budget_exhausted', result)
        self.assertIn('Per-package check budget exhausted', result['error'])
        b_unit = next(e for e in result['events']
                      if e['package'] == 'pkg/b' and e['boundary'] == 'unit')
        self.assertEqual(b_unit['seconds'], 255)
        self.assertEqual(b_unit['remaining'], 250)
        b_unit_bucket = sum(
            e['seconds'] for e in result['events']
            if e['package'] == 'pkg/b'
            and e['boundary'] in ('setup', 'coverage', 'unit'))
        self.assertEqual(b_unit_bucket, 305)


# G9-CHAIN fixtures: a test-file initializer chain (var relay = Allowed;
# var check = relay) and, for the kept leg, a legal initializer diamond:
# relay feeds echo, echo feeds left and right, both combine into `both`,
# check starts there — so the transitive walk re-discovers one declared
# symbol (echo) from two paths and must deduplicate and terminate. Go
# rejects textual initializer cycles outright (initialization-cycle
# compile error, even through function-literal bodies), so termination
# is stressed by fan-out/fan-in re-discovery; the walk's seen-identity
# guard remains a defensive bound beyond what legal Go can express.
G9_CHAIN_TESTS = (
    'package auth\nimport "testing"\n'
    'var relay = Allowed\n'
    'var check = relay\n'
    'func TestCallback(t *testing.T) { _ = check(0); _ = Other(1) }\n'
)
G9_CHAIN_SWAP = G9_CHAIN_TESTS.replace('var check = relay',
                                       'var check = Alternate')
G9_CHAIN_KEPT_TESTS = (
    'package auth\nimport "testing"\n'
    'var relay = Allowed\n'
    'var echo = relay\n'
    'var left = echo\n'
    'var right = echo\n'
    'var both = func(n int) bool { return left(n) && right(n) }\n'
    'var check = both\n'
    'func TestCallback(t *testing.T) { _ = check(0); _ = Other(1) }\n'
)
G9_CHAIN_KEPT_SWAP = G9_CHAIN_KEPT_TESTS.replace(
    'var check = both', 'var check = Alternate') + G8R_CALLBACK_KEEPS

# G9-RECV fixtures: one method per file at the baseline; the current
# tree moves Beta.Check into a.go (where unexecuted Alpha.Check lived),
# relocates Alpha.Check to alpha.go and deletes b.go. Check(n) is one
# block at line 2 of whichever file declares it.
G9_RECV_POLICY = G7_POLICY_BLOCKS + 'type Alpha int\ntype Beta int\n'
G9_RECV_ALPHA = ('package auth\n'
                 'func (a Alpha) Check(n int) bool { return n > Limit }\n')
G9_RECV_BETA = ('package auth\n'
                'func (b Beta) Check(n int) bool { return n > Limit }\n')
G9_RECV_BASE_TESTS = (
    'package auth\nimport "testing"\n'
    'func TestCheck(t *testing.T) {\n'
    '\tvar beta Beta\n'
    '\tif !beta.Check(6) { t.Fatal("false deny") }\n'
    '\tif beta.Check(1) { t.Fatal("deny bypass") }\n'
    '}\n'
)
# Loss shape: TestCheck no longer executes any Check; TestAlpha keeps
# the relocated Alpha.Check executed, which is exactly what let the
# pre-repair selector hide the Beta loss behind a like-name match.
G9_RECV_LOST_TESTS = (
    'package auth\nimport "testing"\n'
    'func TestCheck(t *testing.T) { _ = Other(1) }\n'
    'func TestAlpha(t *testing.T) {\n'
    '\tvar alpha Alpha\n'
    '\tif !alpha.Check(6) { t.Fatal("false deny") }\n'
    '}\n'
)
# Block-preserving shape: the rewritten TestCheck still executes
# Beta.Check at its moved a.go location; TestAlpha keeps compiling
# coverage of Alpha.Check.
G9_RECV_KEPT_TESTS = (
    'package auth\nimport "testing"\n'
    'func TestCheck(t *testing.T) {\n'
    '\tvar beta Beta\n'
    '\tif !beta.Check(6) { t.Fatal("false deny") }\n'
    '\t_ = Other(1)\n'
    '}\n'
    'func TestAlpha(t *testing.T) {\n'
    '\tvar alpha Alpha\n'
    '\tif !alpha.Check(6) { t.Fatal("false deny") }\n'
    '}\n'
)
G9_RECV_LOST_REASON = ('lost_unit_coverage: pkg/auth: TestCheck no '
                       'longer exercises Check')
G9_RECV_BASE_BLOCK = ('pkg/auth/b.go', 2)
G9_RECV_MOVED_BLOCK = ('pkg/auth/a.go', 2)

# G9-EXPORT fixtures: a second critical package importing pkg/auth and
# consuming its exported Limit; and the unexported margin counterpart.
G9_EXPORT_AUTH_TESTS = ('package auth\nimport "testing"\n'
                        'func TestAllowed(t *testing.T) { _ = Allowed(1) }\n')
G9_EXPORT_SUB_USE = (
    'package sub\n\n'
    'import "example.test/critical/pkg/auth"\n\n'
    'func UsesLimit(n int) bool { return n < auth.Limit }\n'
)
G9_EXPORT_SUB_TESTS = ('package sub\nimport "testing"\n'
                       'func TestUsesLimit(t *testing.T) { _ = UsesLimit(1) }\n')
G9_EXPORT_NARROW_POLICY = G7_POLICY_BLOCKS.replace(
    'func Other(n int) int { return n+1 }',
    'const margin = 2\nfunc Other(n int) int { return n+margin }')

# G9-INIT fixtures: two legal func init() declarations in one file.
G9_INIT_POLICY = G7_POLICY_BLOCKS + (
    'func init() { _ = Other(1) }\n'
    'func init() { _ = Allowed(2) }\n'
)
G9_INIT_TESTS = ('package auth\nimport "testing"\n'
                 'func TestSteady(t *testing.T) { _ = Allowed(3); '
                 '_ = Other(4) }\n')
G9_INIT_BOTH_CHANGED = (G9_INIT_POLICY
                        .replace('_ = Other(1)', '_ = Allowed(1)')
                        .replace('_ = Allowed(2)', '_ = Other(2)'))
G9_INIT_SECOND_CHANGED = G9_INIT_POLICY.replace('_ = Allowed(2)',
                                                '_ = Other(2)')


class G9OmissionRepairControls(G8RSelectionRegressionControls):
    """Expectations-first controls for the four r11 selector omissions.

    Each control runs the real selector pipeline against real git
    fixture repositories and the real Go toolchain, inheriting the
    G7_SELECTOR_TREE three-outcome contract. Discriminating legs
    (chained-initializer loss and kept, moved-receiver loss,
    exported-constant importing selection, two-changed init rows) fail
    against the pre-repair tree by construction; the block-preserving
    receiver rewrite and the one-changed init row are acceptance legs
    that must hold on both trees.
    """

    def write_receiver_repo(self, current_tests):
        """Receiver fixture: split methods at base, moved at current."""
        root, _ = self.write_repo(G9_RECV_POLICY, G9_RECV_BASE_TESTS)
        (root / 'pkg/auth/a.go').write_text(G9_RECV_ALPHA)
        (root / 'pkg/auth/b.go').write_text(G9_RECV_BETA)
        base = self.commit_fixture(root, 'receiver split')
        (root / 'pkg/auth/a.go').write_text(G9_RECV_BETA)
        (root / 'pkg/auth/alpha.go').write_text(G9_RECV_ALPHA)
        (root / 'pkg/auth/b.go').unlink()
        (root / 'pkg/auth/policy_test.go').write_text(current_tests)
        return root, base

    def write_two_package_repo(self, policy):
        """Auth policy plus an importing pkg/auth/sub at the baseline."""
        root, _ = self.write_repo(policy, G9_EXPORT_AUTH_TESTS)
        (root / 'pkg/auth/sub').mkdir()
        (root / 'pkg/auth/sub/use.go').write_text(G9_EXPORT_SUB_USE)
        (root / 'pkg/auth/sub/use_test.go').write_text(G9_EXPORT_SUB_TESTS)
        base = self.commit_fixture(root, 'add importing package')
        return root, base

    def run_selector_packages(self, root, base):
        """Real selector run reporting every selected package's rows."""
        code = (
            'import json,sys\n'
            'from pathlib import Path\n'
            'sys.path.insert(0,sys.argv[1])\n'
            'import critical,critical_scope,critical_conservative as cc\n'
            'rows=critical_scope.targets(Path.cwd(),sys.argv[2],'
            "{'critical_paths':['pkg/auth/**'],'build_tags':['']})\n"
            'widened={p:(cc.EVIDENCE["packages"].get(p) or {}).'
            'get("widened") for p in rows}\n'
            'print(json.dumps({"rows":rows,"widened":widened}))\n'
        )
        return run_guarded(['python3', '-c', code, self.selector_tree(), base],
                           cwd=root, timeout=180, env=self.selector_env())

    def test_chained_initializer_swap_blocks_lost_coverage(self):
        # G9-CHAIN-LOSS: swapping the head of an initializer chain
        # (var check = relay → Alternate) must bind the whole previous
        # chain, including the Allowed only relay's initializer reached.
        # One-hop previous-side expansion sees only relay and lets the
        # silent narrow pass stand — the pre-repair escape.
        root, base = self.write_repo(G8R_CALLBACK_POLICY, G9_CHAIN_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G9_CHAIN_SWAP)
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G8R_CALLBACK_LOST_REASON, proc.stdout + proc.stderr)

    def test_chained_initializer_swap_with_kept_coverage_rebaselines(self):
        # G9-CHAIN-KEPT acceptance leg through a legal initializer
        # diamond: TestKeeps keeps every baseline block of the chained
        # initializer-reached consumers, so the swap re-baselines the
        # baseline-executed pair Allowed, Other while the transitive
        # walk deduplicates echo — reached through both left and right
        # — and terminates. Against the pre-repair tree this control
        # fails: Allowed never enters the previous closure and the
        # pair degenerates to TestCallback → Other.
        root, base = self.write_repo(G8R_CALLBACK_POLICY,
                                     G9_CHAIN_KEPT_TESTS)
        (root / 'pkg/auth/policy_test.go').write_text(G9_CHAIN_KEPT_SWAP)
        proc = self.run_selector_records(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assert_callback_swap_demands(
            result, ['TestCallback → Allowed, Other'])
        self.assert_alternate_newly_executed(result)

    def test_declaration_refs_walk_terminates_on_synthetic_cycle(self):
        # G9-CHAIN-WALK unit control for the cycle bound: a synthetic
        # side whose nameless var declarations form a reference cycle
        # (ringStart → ringStep → ringStart) with distinct body hashes,
        # plus a same-symbol twin of ringStart carrying one further
        # ref. The transitive walk must terminate and return the
        # complete bounded ref set — twin included, proving unit
        # identity is (symbols, body hash). Package-level initializer
        # cycles are a Go compile error, so this bound is guarded here
        # at unit level and is not real Go execution.
        cc = self.selector_conservative()

        def var_unit(hash_id, symbols, refs):
            return {'name': '', 'recv': '', 'start': 2, 'end': 2,
                    'hash': hash_id, 'kind': 'var', 'symbols': symbols,
                    'refs': refs, 'selrefs': [], 'lits': [], 'flags': []}

        side = cc.Side([{'path': 'pkg/auth/policy_test.go', 'units': [
            var_unit('hash-check', ['check'], ['ringStart']),
            var_unit('hash-ring-start', ['ringStart'], ['ringStep']),
            var_unit('hash-ring-step', ['ringStep'], ['ringStart']),
            var_unit('hash-ring-start-twin', ['ringStart'], ['Allowed']),
        ]}], Path('.'))
        refs, floors, selrefs = cc.declaration_refs({'check'}, side)
        self.assertEqual(refs, {'ringStart', 'ringStep', 'Allowed'})
        self.assertEqual(floors, set())
        self.assertEqual(selrefs, set())

    def test_moved_receiver_counterpart_blocks_lost_coverage(self):
        # G9-RECV-LOSS: TestCheck rewrote away from Beta.Check while
        # Beta.Check moved into a.go — the file where never-executed
        # Alpha.Check lived at base — and Alpha.Check relocated to the
        # new alpha.go. The base counterpart must preserve (name,
        # receiver): Beta.Check's baseline proof lives at b.go, not
        # behind the same-file Alpha.Check the pre-repair match
        # settled on. TestAlpha keeps the relocated method executed —
        # exactly the company that let the pre-repair selector
        # re-baseline Check from Alpha and return exit zero.
        root, base = self.write_receiver_repo(G9_RECV_LOST_TESTS)
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(G9_RECV_LOST_REASON, proc.stdout + proc.stderr)

    def test_moved_receiver_block_preserving_rewrite_rebaselines(self):
        # G9-RECV-KEPT acceptance leg: the rewritten TestCheck still
        # executes Beta.Check at its moved a.go location, so the
        # obligation legitimately re-baselines. Raw retained profiles
        # prove the block executed at b.go in the base tree and at a.go
        # in the current tree of this one run — the moved-receiver
        # counterpart resolved against the right span.
        root, base = self.write_receiver_repo(G9_RECV_KEPT_TESTS)
        proc = self.run_selector_records(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result['rebaselined'], ['TestCheck → Check'],
                         json.dumps(result, sort_keys=True))
        base_count = self.block_execution(
            self.observed_profile(result, 'base tree')['profile'],
            G9_RECV_BASE_BLOCK)
        current_count = self.block_execution(
            self.observed_profile(result, 'current tree')['profile'],
            G9_RECV_MOVED_BLOCK)
        self.assertGreater(base_count, 0)
        self.assertGreater(current_count, 0)

    def test_exported_constant_change_selects_importing_package(self):
        # G9-EXPORT-SELECT: an exported Limit edit with an in-package
        # consumer keeps pkg/auth narrow (Allowed, seed, no widening)
        # while pkg/auth/sub — which consumes auth.Limit through the
        # import — is selected widened with seed demands. The pre-repair
        # selector left sub entirely absent from the result.
        root, base = self.write_two_package_repo(G7_POLICY_BLOCKS)
        (root / 'pkg/auth/policy.go').write_text(
            G7_POLICY_BLOCKS.replace('const Limit=5', 'const Limit=6'))
        proc = self.run_selector_packages(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(sorted(result['rows']),
                         ['pkg/auth', 'pkg/auth/sub'],
                         json.dumps(result, sort_keys=True))
        auth = result['rows']['pkg/auth']
        self.assertEqual([row['name'] for row in auth], ['Allowed'],
                         json.dumps(auth))
        self.assertTrue(all(row['seed'] for row in auth),
                        json.dumps(auth))
        self.assertIsNone(result['widened']['pkg/auth'],
                          json.dumps(result, sort_keys=True))
        sub = result['rows']['pkg/auth/sub']
        self.assertEqual([row['name'] for row in sub], ['UsesLimit'],
                         json.dumps(sub))
        self.assertTrue(all(row['seed'] for row in sub),
                        json.dumps(sub))
        sub_widened = result['widened']['pkg/auth/sub']
        self.assertIsNotNone(sub_widened, json.dumps(result, sort_keys=True))
        self.assertTrue(any('cross-package consumer of changed declaration'
                            in reason for reason in sub_widened),
                        json.dumps(sub_widened))
        self.assertTrue(any('exported constant consumer: Limit'
                            in reason for reason in sub_widened),
                        json.dumps(sub_widened))

    def test_unexported_constant_change_stays_narrow(self):
        # G9-EXPORT-NARROW acceptance leg: an unexported margin edit
        # with an in-package consumer selects exactly Other in
        # pkg/auth and never reaches the importing package — the
        # cross-package mark is reserved for exported declarations.
        root, base = self.write_two_package_repo(G9_EXPORT_NARROW_POLICY)
        (root / 'pkg/auth/policy.go').write_text(
            G9_EXPORT_NARROW_POLICY.replace('const margin = 2',
                                            'const margin = 3'))
        proc = self.run_selector_packages(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(sorted(result['rows']), ['pkg/auth'],
                         json.dumps(result, sort_keys=True))
        auth = result['rows']['pkg/auth']
        self.assertEqual([row['name'] for row in auth], ['Other'],
                         json.dumps(auth))
        self.assertTrue(all(row['seed'] for row in auth),
                        json.dumps(auth))
        self.assertIsNone(result['widened']['pkg/auth'],
                          json.dumps(result, sort_keys=True))

    def test_two_changed_init_declarations_keep_two_rows(self):
        # G9-INIT-TWO: two legal func init() declarations in one file,
        # both bodies changed, are two selected rows with two seed
        # demands — occurrence and body identity distinguish them. The
        # pre-repair (file, name, receiver) key collapsed them to one
        # row, silently halving the checking demand.
        root, base = self.write_repo(G9_INIT_POLICY, G9_INIT_TESTS)
        (root / 'pkg/auth/policy.go').write_text(G9_INIT_BOTH_CHANGED)
        result = self.selector_output(root, base)
        self.assertEqual([row['name'] for row in result['rows']],
                         ['init', 'init'], json.dumps(result['rows']))
        self.assertTrue(all(row['seed'] for row in result['rows']),
                        json.dumps(result['rows']))
        self.assertEqual(result['seed_demands'], ['init', 'init'])
        self.assertIsNone(result['widened'])
        self.assertEqual(result['reasons'],
                         {'init': ['changed function: init']})

    def test_one_changed_init_declaration_keeps_one_row(self):
        # G9-INIT-ONE acceptance leg: changing only the second init()
        # keeps the unchanged twin spent by body identity, so exactly
        # one init row carries the checking demand.
        root, base = self.write_repo(G9_INIT_POLICY, G9_INIT_TESTS)
        (root / 'pkg/auth/policy.go').write_text(G9_INIT_SECOND_CHANGED)
        result = self.selector_output(root, base)
        self.assertEqual([row['name'] for row in result['rows']],
                         ['init'], json.dumps(result['rows']))
        self.assertTrue(all(row['seed'] for row in result['rows']),
                        json.dumps(result['rows']))
        self.assertEqual(result['seed_demands'], ['init'])
        self.assertIsNone(result['widened'])


# G10-INIT fixtures: occurrence-aware accounting for repeated init() funcs.
G10_INIT_ONE_REMOVED = G7_POLICY_BLOCKS + 'func init() { _ = Allowed(2) }\n'
G10_INIT_DUP_POLICY = G7_POLICY_BLOCKS + (
    'func init() { _ = Allowed(2) }\n'
    'func init() { _ = Allowed(2) }\n'
)

# G10-EXPORT fixtures: unexported constants feeding exported aliases.
G10_ALIAS_POLICY = (
    'package auth\n'
    'const limit = 5\n'
    'const Limit = limit\n'
    'func Allowed(n int) bool { return n <= Limit }\n'
    'func Other(n int) int { return n+1 }\n'
)
G10_ALIAS_CHANGED = G10_ALIAS_POLICY.replace('const limit = 5',
                                             'const limit = 6')
G10_NARROW_POLICY = (
    'package auth\n'
    'const Limit = 5\n'
    'const margin = 2\n'
    'const floor = margin\n'
    'func Other(n int) int { return n+floor }\n'
    'func Allowed(n int) bool { return n <= Limit }\n'
)
G10_NARROW_CHANGED = G10_NARROW_POLICY.replace('const margin = 2',
                                               'const margin = 3')
G10_NARROW_NO_CONSUMER_POLICY = (
    'package auth\n'
    'const limit = 5\n'
    'const inner = limit\n'
    'func Allowed(n int) bool { return n <= 5 }\n'
    'func Other(n int) int { return n+1 }\n'
)


class G10OmissionRepairControls(G9OmissionRepairControls):
    """Controls for the post-G9 init-removal and exported-alias omissions.

    Discriminating legs (one-of-two init removal, same-body duplicate
    removal, unexported-constant-to-exported-alias importer selection)
    fail against the pre-repair tree by construction; the unchanged
    twin-init, edited-init and purely-unexported-reach legs are
    acceptance behavior that must hold on both trees.
    """

    def assert_init_removal_obligation(self, result, raw):
        """A removed repeated init stays a named widening obligation."""
        self.assertTrue(any('removed' in reason and 'init' in reason
                            for reason in result['widened'] or []), raw)
        self.assertTrue(all(row['seed'] for row in result['rows']),
                        raw)

    def test_removing_one_of_two_inits_keeps_removal_obligation(self):
        # G10-INIT-REMOVED: existence accounting must count occurrences
        # of legal repeated declarations. Deleting one of two init()
        # functions leaves a same-named survivor, so a set-based
        # existence check hides the removal entirely; occurrence
        # accounting keeps it a named widening obligation.
        root, base = self.write_repo(G9_INIT_POLICY, G9_INIT_TESTS)
        (root / 'pkg/auth/policy.go').write_text(G10_INIT_ONE_REMOVED)
        proc = self.run_selector(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(result['widened'] or result['rows'],
                        proc.stdout)
        self.assertIn('init', proc.stdout)
        self.assert_init_removal_obligation(result, proc.stdout)

    def test_same_body_duplicate_init_removal_keeps_obligation(self):
        # G10-INIT-DUP: two identical func init() bodies are two legal
        # occurrences. Removing one must not be collapsed away by body
        # identity — the survivor spends one occurrence and the second
        # baseline occurrence keeps its removal obligation.
        root, base = self.write_repo(G10_INIT_DUP_POLICY, G9_INIT_TESTS)
        (root / 'pkg/auth/policy.go').write_text(G10_INIT_ONE_REMOVED)
        proc = self.run_selector(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(result['widened'] or result['rows'],
                        proc.stdout)
        self.assertIn('init', proc.stdout)
        self.assert_init_removal_obligation(result, proc.stdout)

    def test_unchanged_two_inits_stay_unselected(self):
        # G10-INIT-UNCHANGED acceptance leg: with neither init touched
        # the selector selects nothing and widens nothing.
        root, base = self.write_repo(G9_INIT_POLICY, G9_INIT_TESTS)
        result = self.selector_output(root, base)
        self.assertEqual(result['rows'], [], json.dumps(result))
        self.assertIsNone(result['widened'], json.dumps(result))
        self.assertEqual(result['reasons'], {}, json.dumps(result))

    def test_editing_one_init_does_not_fabricate_removal(self):
        # G10-INIT-EDIT acceptance leg: an edited init is a changed
        # function — its occurrence is spent by body matching, so the
        # occurrence accounting must not also report a removal.
        root, base = self.write_repo(G9_INIT_POLICY, G9_INIT_TESTS)
        (root / 'pkg/auth/policy.go').write_text(G9_INIT_SECOND_CHANGED)
        result = self.selector_output(root, base)
        self.assertEqual([row['name'] for row in result['rows']],
                         ['init'], json.dumps(result['rows']))
        self.assertTrue(all(row['seed'] for row in result['rows']),
                        json.dumps(result['rows']))
        self.assertEqual(result['seed_demands'], ['init'])
        self.assertIsNone(result['widened'], json.dumps(result))
        self.assertEqual(result['reasons'],
                         {'init': ['changed function: init']},
                         json.dumps(result))

    def test_unexported_constant_feeding_exported_alias_selects_importer(self):
        # G10-EXPORT-ALIAS: exportedness is a property of the transitive
        # reach, not only of the edited symbol. Changing the unexported
        # limit that feeds the exported Limit keeps pkg/auth precise
        # (Allowed, seed, no widening) while pkg/auth/sub — consuming
        # auth.Limit through the import — is selected widened. The
        # pre-repair selector tested only the edited symbol and left
        # the importing package absent.
        root, base = self.write_two_package_repo(G10_ALIAS_POLICY)
        (root / 'pkg/auth/policy.go').write_text(G10_ALIAS_CHANGED)
        proc = self.run_selector_packages(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(sorted(result['rows']),
                         ['pkg/auth', 'pkg/auth/sub'],
                         json.dumps(result, sort_keys=True))
        auth = result['rows']['pkg/auth']
        self.assertEqual([row['name'] for row in auth], ['Allowed'],
                         json.dumps(auth))
        self.assertTrue(all(row['seed'] for row in auth),
                        json.dumps(auth))
        self.assertIsNone(result['widened']['pkg/auth'],
                          json.dumps(result, sort_keys=True))
        sub = result['rows']['pkg/auth/sub']
        self.assertEqual([row['name'] for row in sub], ['UsesLimit'],
                         json.dumps(sub))
        self.assertTrue(all(row['seed'] for row in sub),
                        json.dumps(sub))
        sub_widened = result['widened']['pkg/auth/sub']
        self.assertIsNotNone(sub_widened, json.dumps(result, sort_keys=True))
        self.assertTrue(any('exported constant consumer: limit'
                            in reason for reason in sub_widened),
                        json.dumps(sub_widened))

    def test_purely_unexported_constant_chain_stays_narrow(self):
        # G10-EXPORT-NARROW acceptance leg: an unexported chain with no
        # exported member keeps the local choice — exactly the in-package
        # consumer Other in pkg/auth, the importing package absent, no
        # widening. Cross-package marking stays reserved for exported
        # reaches.
        root, base = self.write_two_package_repo(G10_NARROW_POLICY)
        (root / 'pkg/auth/policy.go').write_text(G10_NARROW_CHANGED)
        proc = self.run_selector_packages(root, base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(sorted(result['rows']), ['pkg/auth'],
                         json.dumps(result, sort_keys=True))
        auth = result['rows']['pkg/auth']
        self.assertEqual([row['name'] for row in auth], ['Other'],
                         json.dumps(auth))
        self.assertTrue(all(row['seed'] for row in auth),
                        json.dumps(auth))
        self.assertIsNone(result['widened']['pkg/auth'],
                          json.dumps(result, sort_keys=True))

    def test_purely_unexported_chain_without_consumers_fails(self):
        # G10-EXPORT-ERROR acceptance leg: with no function consuming
        # the unexported chain the explicit coverage-decision error
        # still fires — reach-generalized exportedness must not turn a
        # purely unexported change into a widening.
        root, base = self.write_repo(G10_NARROW_NO_CONSUMER_POLICY,
                                     G9_EXPORT_AUTH_TESTS)
        (root / 'pkg/auth/policy.go').write_text(
            G10_NARROW_NO_CONSUMER_POLICY.replace('const limit = 5',
                                                  'const limit = 6'))
        proc = self.run_selector(root, base)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('Unexported constant change without production '
                      'consumers needs an explicit coverage decision: '
                      'pkg/auth:limit', proc.stdout + proc.stderr)


class R2SelectorRepairControls(unittest.TestCase):
    """Row-level controls for indirect dispatch, external test packages
    and shared deadlines."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='critical-r2-rows-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.helper = Path(critical.__file__).parent / 'units.go'
        # Guard sessions created by guarded_helper are drained at
        # teardown — after the test's own observations — so no control
        # ends while a session-owned process group remains.
        self._guard_sids = []
        self.addCleanup(self._drain_guard_sids)

    def write_module(self, name, files):
        base = self.root / name
        base.mkdir(parents=True, exist_ok=True)
        (base / 'go.mod').write_text(f'module example.test/{name}\n\ngo 1.27\n')
        for rel, text in files.items():
            target = base / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        return base

    def run_units(self, module, paths, modes, helper=None):
        request = json.dumps({'paths': paths, 'modes': modes})
        env = dict(os.environ, GOWORK='off', GOFLAGS='', GOTOOLCHAIN='go1.27.4')
        run = subprocess.run(['go', 'run', str(helper or self.helper)], cwd=module,
                             input=request, text=True, capture_output=True,
                             env=env, timeout=110)
        self.assertEqual(run.returncode, 0, run.stderr[:400])
        return {row['path']: row for row in json.loads(run.stdout)}

    @staticmethod
    def unit(row, name):
        return next(u for u in row['units'] if u['name'] == name)

    def test_mv01_function_field_value_keeps_dynamic_obligation(self):
        """MV-01 coordinator replay: fn := h.Allowed; fn(6) must keep the
        field's dynamic uncertainty; the composite-literal value binding
        stays a definite reference and no fallback is involved."""
        module = self.write_module('fnvalue', {
            'auth.go': ('package auth\n\nconst Limit = 5\n\n'
                        'func Allowed(n int) bool { return n > Limit }\n\n'
                        'func Neighbor() bool { return true }\n\n'
                        'func Guarded(n int) bool { return n > 0 }\n'),
            'fnvalue_test.go': ('package auth\n\nimport "testing"\n\n'
                                'type holder struct{ Allowed func(int) bool }\n\n'
                                'func TestFunctionFieldValue(t *testing.T) {\n'
                                '\th := holder{Allowed: Allowed}\n'
                                '\tfn := h.Allowed\n'
                                '\tif !fn(6) {\n'
                                '\t\tt.Fatal("allowed function field value must execute")\n'
                                '\t}\n}\n'),
        })
        rows = self.run_units(module, ['auth.go', 'fnvalue_test.go'], [[]])
        row = self.unit(rows['fnvalue_test.go'], 'TestFunctionFieldValue')
        self.assertIn('Allowed', row.get('selrefs') or [], row)
        self.assertIn('Allowed', row.get('refs') or [], row)
        self.assertEqual(rows['fnvalue_test.go'].get('resolution') or [], [])

    def test_mv01_capture_variants_and_method_value(self):
        """MV-01 variants: parenthesized and direct field calls keep the
        uncertainty; a concrete method-value capture stays a definite
        reference and must not inherit it."""
        module = self.write_module('fnvariants', {
            'auth.go': ('package auth\n\nconst Limit = 5\n\n'
                        'func Allowed(n int) bool { return n > Limit }\n\n'
                        'type holder struct{ Allowed func(int) bool }\n\n'
                        'type gate struct{}\n\n'
                        'func (g gate) Open(n int) bool { return n > 0 }\n'),
            'variants_test.go': ('package auth\n\nimport "testing"\n\n'
                                 'func TestParen(t *testing.T) {\n'
                                 '\tvar h holder\n'
                                 '\th.Allowed = Allowed\n'
                                 '\tif !((h.Allowed)(6)) {\n'
                                 '\t\tt.Fatal("paren call must keep the field obligation")\n'
                                 '\t}\n}\n\n'
                                 'func TestDirectCall(t *testing.T) {\n'
                                 '\tvar h holder\n'
                                 '\th.Allowed = Allowed\n'
                                 '\tif !h.Allowed(6) {\n'
                                 '\t\tt.Fatal("direct call must stay uncertain")\n'
                                 '\t}\n}\n\n'
                                 'func TestMethodValue(t *testing.T) {\n'
                                 '\tvar g gate\n'
                                 '\tm := g.Open\n'
                                 '\tif !m(1) {\n'
                                 '\t\tt.Fatal("method value must bind exactly")\n'
                                 '\t}\n}\n'),
        })
        rows = self.run_units(module, ['auth.go', 'variants_test.go'], [[]])
        paren = self.unit(rows['variants_test.go'], 'TestParen')
        direct = self.unit(rows['variants_test.go'], 'TestDirectCall')
        method = self.unit(rows['variants_test.go'], 'TestMethodValue')
        self.assertIn('Allowed', paren.get('selrefs') or [], paren)
        self.assertIn('Allowed', direct.get('selrefs') or [], direct)
        self.assertIn('Open', method.get('refs') or [], method)
        self.assertNotIn('Open', method.get('selrefs') or [], method)

    def test_ext01_external_test_binds_production_target(self):
        """EXT-01 coordinator replay: package auth_test's direct target
        call binds Allowed exactly through package-path identity, the
        import alias stays a reference, and no fallback note appears."""
        module = self.write_module('fnvalue', {
            'auth.go': ('package auth\n\nconst Limit = 5\n\n'
                        'func Allowed(n int) bool { return n > Limit }\n\n'
                        'func Neighbor() bool { return true }\n\n'
                        'func Guarded(n int) bool { return n > 0 }\n'),
            'fnvalue_test.go': ('package auth\n\nimport "testing"\n\n'
                                'type holder struct{ Allowed func(int) bool }\n\n'
                                'func TestFunctionFieldValue(t *testing.T) {\n'
                                '\th := holder{Allowed: Allowed}\n'
                                '\tfn := h.Allowed\n'
                                '\tif !fn(6) {\n'
                                '\t\tt.Fatal("allowed function field value must execute")\n'
                                '\t}\n}\n'),
            'external_test.go': ('package auth_test\n\nimport (\n'
                                 '\t"testing"\n\n'
                                 '\t"example.test/fnvalue"\n)\n\n'
                                 'func TestExternalAllowed(t *testing.T) {\n'
                                 '\tif !auth.Allowed(6) {\n'
                                 '\t\tt.Fatal("external production call must execute")\n'
                                 '\t}\n}\n'),
        })
        rows = self.run_units(module, ['auth.go', 'fnvalue_test.go', 'external_test.go'], [[]])
        row = self.unit(rows['external_test.go'], 'TestExternalAllowed')
        self.assertIn('Allowed', row.get('refs') or [], row)
        self.assertIn('auth', row.get('refs') or [], row)
        for path, out in rows.items():
            self.assertEqual(out.get('resolution') or [], [], (path, out.get('resolution')))

    def test_ext01_foreign_same_named_stay_excluded(self):
        """EXT-01 exclusion: foreign same-named functions and methods
        never bind to the analyzed target, while the same external test
        package's genuine target references do."""
        module = self.write_module('fnforeign', {
            'auth.go': ('package auth\n\n'
                        'func Allowed(n int) bool { return n > 0 }\n\n'
                        'type Gate struct{}\n\n'
                        'func (g Gate) Open(n int) bool { return n > 0 }\n'),
            'pkg/other/other.go': ('package other\n\n'
                                   'func Allowed(n int) bool { return n < 0 }\n\n'
                                   'type OtherGate struct{}\n\n'
                                   'func (g OtherGate) Open(n int) bool { return n < 0 }\n'),
            'foreign_test.go': ('package auth_test\n\nimport (\n'
                                '\t"testing"\n\n'
                                '\t"example.test/fnforeign"\n'
                                '\t"example.test/fnforeign/pkg/other"\n)\n\n'
                                'func TestForeignOnly(t *testing.T) {\n'
                                '\tif !other.Allowed(6) {\n'
                                '\t\tt.Fatal("foreign call must execute")\n'
                                '\t}\n'
                                '\tog := other.OtherGate{}\n'
                                '\tif !og.Open(1) {\n'
                                '\t\tt.Fatal("foreign method must execute")\n'
                                '\t}\n}\n\n'
                                'func TestTarget(t *testing.T) {\n'
                                '\tif !auth.Allowed(6) {\n'
                                '\t\tt.Fatal("target call must execute")\n'
                                '\t}\n'
                                '\tg := auth.Gate{}\n'
                                '\tif !g.Open(1) {\n'
                                '\t\tt.Fatal("target method must execute")\n'
                                '\t}\n}\n'),
        })
        rows = self.run_units(module, ['auth.go', 'foreign_test.go'], [[]])
        foreign = self.unit(rows['foreign_test.go'], 'TestForeignOnly')
        target = self.unit(rows['foreign_test.go'], 'TestTarget')
        self.assertEqual(sorted(foreign.get('refs') or []), ['other', 'testing'], foreign)
        # Foreign names stay out of both reference fields of the
        # foreign test's unit — not merely out of refs.
        self.assertEqual(foreign.get('selrefs') or [], [], foreign)
        self.assertNotIn('Allowed', (foreign.get('refs') or [])
                         + (foreign.get('selrefs') or []), foreign)
        self.assertNotIn('Open', (foreign.get('refs') or [])
                         + (foreign.get('selrefs') or []), foreign)
        self.assertIn('Allowed', target.get('refs') or [], target)
        self.assertIn('Open', target.get('refs') or [], target)
        for path, out in rows.items():
            self.assertEqual(out.get('resolution') or [], [], (path, out.get('resolution')))

    def test_ext01_external_helper_traverses_to_production_target(self):
        """EXT-01 follow-up: an external test package helper calling the
        production target keeps the exact traversal — the helper units
        own the target function and concrete-method references, the
        calling test owns the helpers — with no fallback note anywhere."""
        module = self.write_module('fnhelper', {
            'auth.go': ('package auth\n\nconst Limit = 5\n\n'
                        'func Allowed(n int) bool { return n > Limit }\n\n'
                        'type Gate struct{}\n\n'
                        'func (g Gate) Open(n int) bool { return n > 0 }\n'),
            'external_helper_test.go': ('package auth_test\n\nimport (\n'
                                        '\t"testing"\n\n'
                                        '\t"example.test/fnhelper"\n)\n\n'
                                        'func externalAllowed() bool {\n'
                                        '\treturn auth.Allowed(6)\n}\n\n'
                                        'func externalGate() bool {\n'
                                        '\tg := auth.Gate{}\n'
                                        '\treturn g.Open(1)\n}\n\n'
                                        'func TestExternalHelper(t *testing.T) {\n'
                                        '\tif !externalAllowed() {\n'
                                        '\t\tt.Fatal("external helper production call must execute")\n'
                                        '\t}\n'
                                        '\tif !externalGate() {\n'
                                        '\t\tt.Fatal("external helper method call must execute")\n'
                                        '\t}\n}\n'),
        })
        rows = self.run_units(module, ['auth.go', 'external_helper_test.go'], [[]])
        helper = self.unit(rows['external_helper_test.go'], 'externalAllowed')
        gate = self.unit(rows['external_helper_test.go'], 'externalGate')
        test = self.unit(rows['external_helper_test.go'], 'TestExternalHelper')
        self.assertIn('Allowed', helper.get('refs') or [], helper)
        self.assertEqual(sorted(helper.get('refs') or []),
                         ['Allowed', 'auth'], helper)
        self.assertIn('Open', gate.get('refs') or [], gate)
        self.assertIn('Gate', gate.get('refs') or [], gate)
        self.assertEqual(sorted(gate.get('refs') or []),
                         ['Gate', 'Open', 'auth'], gate)
        self.assertEqual(sorted(test.get('refs') or []),
                         ['externalAllowed', 'externalGate', 'testing'], test)
        for path, out in rows.items():
            self.assertEqual(out.get('resolution') or [], [], (path, out.get('resolution')))

    def test_ext01_conservative_final_selection_after_test_only_edit(self):
        """EXT-01 follow-up: a test-only fingerprint edit of the external
        helper must keep production Allowed in the independent
        conservative final selection — not merely in raw helper rows —
        selecting exactly the bound target instead of widening."""
        module = self.write_module('fnconsel', {
            'pkg/auth/auth.go': ('package auth\n\nconst Limit = 5\n\n'
                                 'func Allowed(n int) bool { return n > Limit }\n\n'
                                 'func Neighbor() bool { return true }\n\n'
                                 'func Guarded(n int) bool { return n > 0 }\n'),
            'pkg/auth/external_helper_test.go': ('package auth_test\n\nimport (\n'
                                                 '\t"testing"\n\n'
                                                 '\t"example.test/fnconsel/pkg/auth"\n)\n\n'
                                                 'func externalAllowed() bool {\n'
                                                 '\treturn auth.Allowed(6)\n}\n\n'
                                                 'func TestExternalHelper(t *testing.T) {\n'
                                                 '\tif !externalAllowed() {\n'
                                                 '\t\tt.Fatal("external helper production call must execute")\n'
                                                 '\t}\n}\n'),
        })
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        # Test-only fingerprint edit: the helper's production call argument
        # changes, so every edited unit's fingerprint changes while no
        # production declaration is touched.
        edited = module / 'pkg/auth/external_helper_test.go'
        edited.write_text(edited.read_text().replace('auth.Allowed(6)',
                                                     'auth.Allowed(7)'))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'test-only fingerprint edit']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV, critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            selected = critical_scope.targets(
                module, base, {'critical_paths': ['pkg/auth/**']})
            evidence = critical_scope.selection_evidence()['pkg/auth']['reasons']
        except ValueError as exc:
            self.fail(f'conservative final selection setup failed before the '
                      f'selection oracle could run: {exc}')
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        names = {fn['name'] for fn in selected.get('pkg/auth', [])}
        self.assertEqual(
            names, {'Allowed'},
            f"conservative final selection must be exactly the bound "
            f"production target: 'Allowed' not found alone in {sorted(names)}")
        self.assertNotIn('*', evidence, evidence)

    # R4 selector-correction and EXT-01 originals come from the embedded
    # FROZEN_BLOBS payloads (module header), hash-verified by frozen_blob
    # before any shadow gate trusts them — no git history needed.

    def ext01_both_paths_module(self, name):
        """EXT-01 reusable fixture: an external test whose helper calls
        production Allowed while the same test also calls production
        Guarded directly, committed as a real git base."""
        module = self.write_module(name, {
            'pkg/auth/auth.go': ('package auth\n\n'
                                 'func Allowed(n int) bool { return n > 0 }\n\n'
                                 'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/auth/external_helper_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                f'\t"example.test/{name}/pkg/auth"\n)\n\n'
                'func externalAllowed() bool {\n'
                '\treturn auth.Allowed(6)\n}\n\n'
                'func TestBothPaths(t *testing.T) {\n'
                '\tif !externalAllowed() {\n'
                '\t\tt.Fatal("helper production call must execute")\n'
                '\t}\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("direct production call must execute")\n'
                '\t}\n}\n'),
        })
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        return module, base

    def test_ext01_baseline_coverage_loss_after_helper_rewrite(self):
        """EXT-01 phase A: an external test whose helper calls production
        Allowed while the same test also calls production Guarded
        directly keeps both in the conservative final selection. The
        discriminating helper-removal oracle — including the frozen
        original and the isolated current mutant — is phase B below and
        never depends on this phase succeeding first."""
        module, base = self.ext01_both_paths_module('fnboth')
        # Independent leg proof A: the base suite really executes
        # Allowed through the helper (and Guarded directly).
        run = subprocess.run(['go', 'test', './...'], cwd=module,
                             capture_output=True, text=True,
                             env=self.go_env(), timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        # Test-only edit for phase A: the helper body stays
        # byte-identical; only the calling test's fingerprint changes.
        testfile = module / 'pkg/auth/external_helper_test.go'
        testfile.write_text(testfile.read_text().replace(
            't.Fatal("direct production call must execute")',
            't.Fatal("direct production call must still execute")'))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'test-only fingerprint edit']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV, critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            selected = critical_scope.targets(
                module, base, {'critical_paths': ['pkg/auth/**']})
            evidence = critical_scope.selection_evidence()['pkg/auth']['reasons']
        except ValueError as exc:
            self.fail(f'phase A lost coverage unexpectedly: {exc}')
        finally:
            critical_conservative.reset_selection()
            critical_conservative.DEADLINES.clear()
            critical_conservative.UNIT_REMAINDERS.clear()
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        names = {fn['name'] for fn in selected.get('pkg/auth', [])}
        self.assertEqual(
            names, {'Allowed', 'Guarded'},
            f"conservative final selection 'Allowed' not found beside "
            f"'Guarded' in {sorted(names)}")
        self.assertNotIn('*', evidence, evidence)

    def test_ext01_missing_helper_rewrite_original_and_isolated_accept(self):
        """EXT-01 phase B (EXT-BASELINE-ORACLE-01): from a fresh base
        fixture with ONLY the helper invocation removed — the helper
        function stays byte-identical and the suite stays green
        executing Guarded — the current gate must raise
        lost_unit_coverage naming Allowed. The frozen original helper
        (8da54a13: no external declaration index, production-only bare
        external identDecision) cannot bind the rewrite, so it WIDENS
        to the whole package under the two no-bindable-consumer
        reasons, every selected row seed-demanding, with no
        rebaselined entry; the isolated current mutant with that index
        alone disabled instead RE-BASELINES the contract to
        "TestBothPaths → Guarded". Which silence loses real coverage
        is decided by the downstream gate, never by this selection
        oracle: the companion full-gate test proves the original's
        widen is enforced (rejected for Allowed's uncovered seed
        obligation) while the isolated re-baseline passes with Allowed
        independently uncovered. Base and rewritten coverage facts are
        proven here through real go test coverage profiles parsed by
        execution counts; policy.HERE selects the exact helper variant
        and is restored with every module/deadline binding in
        finally."""
        module, base = self.ext01_both_paths_module('fnboth2')
        testfile = module / 'pkg/auth/external_helper_test.go'
        authfile = module / 'pkg/auth/auth.go'

        def covered_lines():
            profile = self.root / 'ext01-cover-profile'
            run = subprocess.run(
                ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
                cwd=module, capture_output=True, text=True,
                env=self.go_env(), timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            counts = {}
            for line in profile.read_text().splitlines():
                if not line or line.startswith('mode:'):
                    continue
                parts = line.split()
                location = parts[0]
                if location.rsplit('/', 1)[-1].split(':')[0] != 'auth.go':
                    continue
                start = int(location.rsplit(':', 1)[1].split('.')[0])
                counts[start] = max(counts.get(start, 0), int(parts[-1]))
            return counts

        def func_line(name):
            return next(index + 1 for index, text_line
                        in enumerate(authfile.read_text().splitlines())
                        if text_line.startswith(f'func {name}'))

        allowed_line, guarded_line = func_line('Allowed'), func_line('Guarded')
        counts = covered_lines()
        self.assertGreaterEqual(
            counts[allowed_line], 1,
            'base suite never executed Allowed through the helper')
        self.assertGreaterEqual(
            counts[guarded_line], 1,
            'base suite never executed Guarded directly')
        # Rewrite: drop ONLY the helper invocation; the helper function
        # itself stays byte-identical and the direct Guarded call keeps
        # the test green.
        testfile.write_text(testfile.read_text().replace(
            '\tif !externalAllowed() {\n'
            '\t\tt.Fatal("helper production call must execute")\n'
            '\t}\n', ''))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'drop helper invocation only']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        counts = covered_lines()
        self.assertGreaterEqual(
            counts[guarded_line], 1,
            'rewritten suite no longer executes Guarded')
        self.assertEqual(
            counts.get(allowed_line, 0), 0,
            'rewritten suite still executes Allowed; the fixture no '
            'longer drops its coverage')

        # Frozen original helper: hash-checked bytes of 8da54a13.
        original = self.root / 'ext01-original'
        original.mkdir()
        original_units = frozen_blob('ext01_units')
        (original / 'units.go').write_text(original_units)
        # Isolated current mutant: only the external declaration index
        # is disabled — decls stays nil — with no compile error.
        isolated = self.root / 'ext01-isolated'
        isolated.mkdir()
        anchor = 'if !samePackage(pkg, target) {'
        source = self.helper.read_text()
        self.assertEqual(source.count(anchor), 1)
        (isolated / 'units.go').write_text(
            source.replace(anchor, 'if false {'))

        real_here = critical_scope.policy.HERE
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV, critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value

        def run_targets():
            return critical_scope.targets(
                module, base, {'critical_paths': ['pkg/auth/**']})

        def reset_budget_state():
            critical_conservative.reset_selection()
            critical_conservative.DEADLINES.clear()
            critical_conservative.UNIT_REMAINDERS.clear()

        try:
            # Fixed: the rewrite loses real baseline coverage and must
            # block loudly, naming the lost function.
            with self.assertRaises(ValueError) as caught:
                run_targets()
            self.assertIn('lost_unit_coverage', str(caught.exception),
                          caught.exception)
            self.assertIn('Allowed', str(caught.exception), caught.exception)
            reset_budget_state()
            # Frozen original: no external declaration index — its rows
            # carry no helper-mediated production bindings, so the
            # rewrite cannot bind and the selection WIDENS to the whole
            # package, every selected row seed-demanding. The full-gate
            # companion test proves that widen is enforced downstream
            # (rejected for Allowed's uncovered seed obligation).
            critical_scope.policy.HERE = original
            selected = run_targets()
            names = {fn['name'] for fn in selected.get('pkg/auth', [])}
            self.assertEqual(names, {'Allowed', 'Guarded'}, sorted(names))
            evidence = critical_scope.selection_evidence()['pkg/auth']
            self.assertEqual(evidence['widened'], [
                'changed test target: TestBothPaths has no bindable '
                'production consumer',
                'lost baseline coverage without bindable consumer: '
                'TestBothPaths'], evidence)
            self.assertIn('*', evidence['reasons'], evidence)
            self.assertNotIn('rebaselined', evidence, evidence)
            self.assertEqual({fn['name']: fn.get('seed')
                              for fn in selected.get('pkg/auth', [])},
                             {'Allowed': True, 'Guarded': True})
            reset_budget_state()
            # Isolated current mutant: the index alone disabled — the
            # rewrite silently RE-BASELINES the contract to Guarded;
            # the full-gate companion test proves the gate then passes
            # with Allowed independently uncovered (the end-to-end
            # silent-loss negative).
            critical_scope.policy.HERE = isolated
            selected = run_targets()
            names = {fn['name'] for fn in selected.get('pkg/auth', [])}
            self.assertEqual(names, {'Guarded'}, sorted(names))
            evidence = critical_scope.selection_evidence()['pkg/auth']
            self.assertIsNone(evidence['widened'], evidence)
            self.assertEqual(evidence['rebaselined'],
                             ['TestBothPaths \u2192 Guarded'], evidence)
            self.assertEqual({fn['name']: fn.get('seed')
                              for fn in selected.get('pkg/auth', [])},
                             {'Guarded': True})
        finally:
            critical_scope.policy.HERE = real_here
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            reset_budget_state()
        self.assertIs(critical_scope.policy.HERE, real_here,
                      'canonical policy binding not restored')

    def test_ext01_full_gate_seed_enforcement_controls(self):
        """EXT-01 full-gate controls: the exact production critical.py
        CLI — real gremlins, the approved 300/420/300 budgets, the
        repository's own config — on a self-contained pkg/auth fixture
        whose only Allowed coverage is the external helper path and
        whose FuzzGuarded target carries the fuzz-seed consumer. With
        the helper invocation alone removed, the frozen original
        helper's whole-package widen must be rejected for exactly
        Allowed's uncovered seed obligation — an enforced conservative
        fallback, not a silent loss — while the isolated
        declaration-index mutant must pass with Allowed independently
        uncovered (the end-to-end silent-loss negative) and real
        FuzzGuarded executions; restoring the invocation leaves the
        production gate with no changed units. Independent coverage
        facts come from go test profiles parsed by execution counts,
        never from the gate's own selection."""
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')
        module = self.write_module('fngate', {
            'pkg/auth/auth.go': ('package auth\n\n'
                                 'func Allowed(n int) bool { return n > 0 }\n\n'
                                 'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/auth/external_helper_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/fngate/pkg/auth"\n)\n\n'
                'func externalAllowed() bool {\n'
                '\treturn auth.Allowed(6)\n}\n\n'
                'func TestBothPaths(t *testing.T) {\n'
                '\tif !externalAllowed() {\n'
                '\t\tt.Fatal("helper production call must execute")\n'
                '\t}\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("direct production call must execute")\n'
                '\t}\n}\n\n'
                'func FuzzGuarded(f *testing.F) {\n'
                '\tf.Add(4)\n'
                '\tf.Fuzz(func(t *testing.T, n int) {\n'
                '\t\tauth.Guarded(n)\n'
                '\t})\n}\n'),
        })
        testfile = module / 'pkg/auth/external_helper_test.go'
        intact = testfile.read_text()
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        env = self.go_env(**{critical_scope.MODE_ENV: critical_scope.CONSERVATIVE})

        def covered_lines():
            profile = self.root / 'ext01-gate-cover'
            run = subprocess.run(
                ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
                cwd=module, capture_output=True, text=True, env=env,
                timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            counts = {}
            for line in profile.read_text().splitlines():
                if not line or line.startswith('mode:'):
                    continue
                parts = line.split()
                location = parts[0]
                if location.rsplit('/', 1)[-1].split(':')[0] != 'auth.go':
                    continue
                start = int(location.rsplit(':', 1)[1].split('.')[0])
                # The final field is the execution count; the statement
                # count is never coverage.
                counts[start] = max(counts.get(start, 0), int(parts[-1]))
            return counts

        def func_line(name):
            source = (module / 'pkg/auth/auth.go').read_text()
            return next(index + 1 for index, text_line
                        in enumerate(source.splitlines())
                        if text_line.startswith(f'func {name}'))

        allowed_line, guarded_line = func_line('Allowed'), func_line('Guarded')
        counts = covered_lines()
        self.assertGreaterEqual(counts[allowed_line], 1,
                                'base never executed Allowed')
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'base never executed Guarded')
        testfile.write_text(intact.replace(
            '\tif !externalAllowed() {\n'
            '\t\tt.Fatal("helper production call must execute")\n\t}\n', ''))
        rewritten = testfile.read_text()
        self.assertIn('func externalAllowed() bool', rewritten)
        self.assertNotIn('externalAllowed()', rewritten.replace(
            'func externalAllowed() bool', ''))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'drop helper invocation only']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        counts = covered_lines()
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'rewrite no longer executes Guarded')
        self.assertEqual(counts.get(allowed_line, 0), 0,
                         'rewrite still executes Allowed')

        # Shadow gates: this repository's current public gate code and
        # config with only units.go swapped for the hash-checked frozen
        # original or the isolated declaration-index mutant. The
        # rewrite is already committed, so --base stays the original
        # base commit, never the rewritten HEAD.
        original_units = frozen_blob('ext01_units')
        anchor = 'if !samePackage(pkg, target) {'
        current_units = self.helper.read_text()
        self.assertEqual(current_units.count(anchor), 1)

        def shadow_gate(name, units_text):
            directory = self.root / name / 'go_policy'
            directory.mkdir(parents=True)
            for item in Path(critical_conservative.__file__).parent.iterdir():
                if item.suffix == '.py' or item.name == 'critical.json':
                    shutil.copyfile(item, directory / item.name)
            (directory / 'units.go').write_text(units_text)
            return directory / 'critical.py'

        def run_gate(cli, out_name):
            out = self.root / out_name
            if out.exists():
                shutil.rmtree(out)
            run = subprocess.run(
                [sys.executable, str(cli), '--root', str(module),
                 '--base', base, '--gremlins', gremlins,
                 '--output', str(out)],
                cwd=self.root, capture_output=True, text=True, env=env,
                timeout=900)
            report_path = out / 'report.json'
            report = (json.loads(report_path.read_text())
                      if report_path.exists() else {})
            return run, report

        # Original: the widen's seed demand is enforced downstream by
        # the fuzz-seed consumer — a rejection, not a silent loss.
        run, report = run_gate(shadow_gate('ext01-gate-original',
                                           original_units),
                               'ext01-gate-out-original')
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(
            report['error'],
            'Fuzz seeds do not cover every changed-function block: '
            'pkg/auth/auth.go:Allowed')
        entry = report['packages']['pkg/auth']
        self.assertEqual({(fn['name'], fn['seed'])
                          for fn in entry['functions']},
                         {('Allowed', True), ('Guarded', True)})
        evidence = report['selector']['evidence']['pkg/auth']
        self.assertEqual(evidence['widened'], [
            'changed test target: TestBothPaths has no bindable '
            'production consumer',
            'lost baseline coverage without bindable consumer: '
            'TestBothPaths'], evidence)
        self.assertIn('*', evidence['reasons'], evidence)
        self.assertNotIn('rebaselined', evidence, evidence)
        # Isolated: the re-baseline passes the full gate while Allowed
        # is independently uncovered — the end-to-end silent-loss
        # negative. Fuzz N/A reasons are never coverage evidence.
        run, report = run_gate(shadow_gate(
            'ext01-gate-isolated',
            current_units.replace(anchor, 'if false {')),
            'ext01-gate-out-isolated')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('Report SHA256: ', run.stdout,
                      run.stdout + run.stderr)
        self.assertEqual(report['status'], 'passed')
        entry = report['packages']['pkg/auth']
        self.assertEqual([(fn['name'], fn['seed'])
                          for fn in entry['functions']],
                         [('Guarded', True)])
        evidence = report['selector']['evidence']['pkg/auth']
        self.assertIsNone(evidence['widened'], evidence)
        self.assertEqual(evidence['rebaselined'],
                         ['TestBothPaths \u2192 Guarded'], evidence)
        checks = entry['checks']
        self.assertEqual(checks['unit:']['status'], 'not_applicable')
        self.assertIn('fuzz-target package', checks['unit:']['reason'])
        self.assertIsInstance(checks['fuzz:']['FuzzGuarded'], int)
        self.assertGreater(checks['fuzz:']['FuzzGuarded'], 0)
        self.assertEqual(checks['mutation:']['status'], 'not_applicable')
        self.assertIn('no gremlins-qualified', checks['mutation:']['reason'])
        # Positive control: restored invocation, production gate, no
        # changed units. HEAD is the rewrite commit, so restoration
        # comes from the captured base bytes, never from checkout.
        testfile.write_text(intact)
        self.assertEqual(testfile.read_text(), intact)
        run, report = run_gate(
            Path(critical_conservative.__file__).parent / 'critical.py',
            'ext01-gate-out-positive')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('Report SHA256: ', run.stdout,
                      run.stdout + run.stderr)
        self.assertEqual(report['status'], 'not_applicable')
        self.assertEqual(report['packages'], {})

    def test_r4_generic_method_origin_binds_qualified_edge(self):
        """EXT-GENERIC-01: a method declared on a generic type of the
        checked external test group binds by its ORIGIN declaration
        when selected through an instantiation — probe[int] and
        probe[T] are one helper — and the reference carries the
        receiver-qualified key probe.allow, never a bare method name.
        Exclusion of foreign same-named methods is covered by the
        existing legal exported-foreign tests. The frozen
        original lost the edge entirely (the declaration index held
        the declared object, the selection resolved an instance), so
        removing the invocation silently dropped the helper's Allowed
        coverage; the isolated origin-index splice reproduces that
        loss end-to-end while the fixed gate blocks on it. Independent
        coverage facts come from go test profiles parsed by execution
        counts, never from the gate's own selection."""
        module = self.write_module('fngeneric', {
            'pkg/auth/auth.go': ('package auth\n\n'
                                 'func Allowed(n int) bool { return n > 0 }\n\n'
                                 'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/auth/generic_helper_test.go': (
                'package auth_test\n\nimport (\n'
                '\t"example.test/fngeneric/pkg/auth"\n)\n\n'
                'type probe[T any] struct{}\n\n'
                'func (probe[T]) allow() bool {\n'
                '\treturn auth.Allowed(6)\n}\n'),
            'pkg/auth/generic_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/fngeneric/pkg/auth"\n)\n\n'
                'func TestGenericMethod(t *testing.T) {\n'
                '\tif mv := (probe[int]{}).allow; !mv() {\n'
                '\t\tt.Fatal("method value must execute")\n'
                '\t}\n'
                '\tif !(probe[int]{}).allow() {\n'
                '\t\tt.Fatal("direct method call must execute")\n'
                '\t}\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("direct production call must execute")\n'
                '\t}\n}\n'),
        })
        original_units = frozen_blob('r4_units')
        current_units = self.helper.read_text()
        isolated_units = current_units.replace(
            '} else if samePackage(methodDeclPkg(obj), target) || decls[obj.Origin()] {',
            '} else if samePackage(methodDeclPkg(obj), target) {')
        self.assertNotEqual(isolated_units, current_units)
        original_path = self.root / 'r4-generic-original-units.go'
        isolated_path = self.root / 'r4-generic-isolated-units.go'
        original_path.write_text(original_units)
        isolated_path.write_text(isolated_units)
        variants = [('fixed', self.helper), ('original', original_path),
                    ('isolated', isolated_path)]
        # One request for one directory keeps the type-checked
        # resolution closed; foreign-method exclusion coverage lives in
        # the existing legal exported-foreign tests.
        paths = ['pkg/auth/auth.go',
                 'pkg/auth/generic_helper_test.go',
                 'pkg/auth/generic_test.go']
        for leg, helper in variants:
            rows = self.run_units(module, paths, [[]], helper=helper)
            caller = self.unit(rows['pkg/auth/generic_test.go'],
                               'TestGenericMethod')
            helper_row = self.unit(rows['pkg/auth/generic_helper_test.go'],
                                   'allow')
            self.assertEqual(helper_row.get('recv'), 'probe', (leg, helper_row))
            self.assertEqual(sorted(helper_row.get('refs') or []),
                             ['Allowed', 'auth', 'probe'], (leg, helper_row))
            self.assertEqual(sorted(helper_row.get('selrefs') or []),
                             [], (leg, helper_row))
            if leg == 'fixed':
                self.assertEqual(sorted(caller.get('refs') or []),
                                 ['Guarded', 'auth', 'probe',
                                  'probe.allow', 'testing'], caller)
                self.assertEqual(caller.get('selrefs') or [], [], caller)
            else:
                # Original and isolated: the instantiation resolves an
                # object the declaration index never held, so the edge
                # vanishes — no qualified key, no bare name — and only
                # the direct Guarded reference survives.
                self.assertEqual(sorted(caller.get('refs') or []),
                                 ['Guarded', 'auth', 'probe',
                                  'testing'], (leg, caller))
                for absent in ('allow', 'probe.allow'):
                    self.assertNotIn(absent,
                                     (caller.get('refs') or []) +
                                     (caller.get('selrefs') or []),
                                     (leg, absent, caller))
            for path in paths[1:]:
                self.assertEqual(rows[path].get('resolution') or [], [],
                                 (leg, path, rows[path].get('resolution')))
        testfile = module / 'pkg/auth/generic_test.go'
        intact = testfile.read_text()
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()

        def covered_lines():
            profile = self.root / 'r4-generic-cover'
            run = subprocess.run(
                ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
                cwd=module, capture_output=True, text=True,
                env=self.go_env(), timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            counts = {}
            for line in profile.read_text().splitlines():
                if not line or line.startswith('mode:'):
                    continue
                parts = line.split()
                location = parts[0]
                if location.rsplit('/', 1)[-1].split(':')[0] != 'auth.go':
                    continue
                start = int(location.rsplit(':', 1)[1].split('.')[0])
                # The final field is the execution count; the statement
                # count is never coverage.
                counts[start] = max(counts.get(start, 0), int(parts[-1]))
            return counts

        def func_line(name):
            source = (module / 'pkg/auth/auth.go').read_text()
            return next(index + 1 for index, text_line
                        in enumerate(source.splitlines())
                        if text_line.startswith(f'func {name}'))

        allowed_line, guarded_line = func_line('Allowed'), func_line('Guarded')
        counts = covered_lines()
        self.assertGreaterEqual(counts[allowed_line], 1,
                                'base never executed Allowed')
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'base never executed Guarded')
        # Phase A — test-only fingerprint edit: the generic method edge
        # keeps the full conservative scope with no widening.
        testfile.write_text(intact.replace(
            'direct production call must execute',
            'direct production call must still execute'))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'test-only fingerprint edit']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV,
                            critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            selected = critical_scope.targets(
                module, base, {'critical_paths': ['pkg/auth/**']})
            evidence = critical_scope.selection_evidence()['pkg/auth']
        except ValueError as exc:
            self.fail(f'phase A lost coverage unexpectedly: {exc}')
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        names = {fn['name'] for fn in selected.get('pkg/auth', [])}
        self.assertEqual(names, {'Allowed', 'Guarded'}, sorted(names))
        self.assertNotIn('*', evidence['reasons'], evidence)
        # Rewrite: drop ONLY both invocation forms; the helper method
        # itself stays byte-identical and the direct Guarded call keeps
        # the test green. HEAD is the rewrite commit, so restoration
        # comes from the captured base bytes, never from checkout.
        testfile.write_text(intact.replace(
            '\tif mv := (probe[int]{}).allow; !mv() {\n'
            '\t\tt.Fatal("method value must execute")\n\t}\n', '').replace(
            '\tif !(probe[int]{}).allow() {\n'
            '\t\tt.Fatal("direct method call must execute")\n\t}\n', ''))
        rewritten = testfile.read_text()
        self.assertNotIn('probe[int]', rewritten)
        self.assertIn('auth.Guarded(2)', rewritten)
        self.assertIn('return auth.Allowed(6)',
                      (module / 'pkg/auth/generic_helper_test.go').read_text())
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'drop generic method invocations only']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        counts = covered_lines()
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'rewrite no longer executes Guarded')
        self.assertEqual(counts.get(allowed_line, 0), 0,
                         'rewrite still executes Allowed')
        # Fixed gate: the qualified edge survives the rewrite in the
        # baseline closure, so the loss is proven, not silent.
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV,
                            critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            with self.assertRaises(ValueError) as caught:
                critical_scope.targets(
                    module, base, {'critical_paths': ['pkg/auth/**']})
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertIn('lost_unit_coverage', str(caught.exception),
                      caught.exception)
        self.assertIn('Allowed', str(caught.exception), caught.exception)
        # Shadow gates: current public gate code and config with only
        # units.go swapped for the hash-checked frozen original or the
        # isolated origin-index splice — both pass while Allowed is
        # independently uncovered, the end-to-end silent-loss negative.
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')

        def shadow_gate(name, units_text):
            directory = self.root / name / 'go_policy'
            directory.mkdir(parents=True)
            for item in Path(critical_conservative.__file__).parent.iterdir():
                if item.suffix == '.py' or item.name == 'critical.json':
                    shutil.copyfile(item, directory / item.name)
            (directory / 'units.go').write_text(units_text)
            return directory / 'critical.py'

        def run_gate(cli, out_name):
            out = self.root / out_name
            if out.exists():
                shutil.rmtree(out)
            run = subprocess.run(
                [sys.executable, str(cli), '--root', str(module),
                 '--base', base, '--gremlins', gremlins,
                 '--output', str(out)],
                cwd=self.root, capture_output=True, text=True,
                env=self.go_env(**{critical_scope.MODE_ENV:
                                   critical_scope.CONSERVATIVE}),
                timeout=600)
            report_path = out / 'report.json'
            report = (json.loads(report_path.read_text())
                      if report_path.exists() else {})
            return run, report

        for leg, units_text in (('original', original_units),
                                ('isolated', isolated_units)):
            run, report = run_gate(shadow_gate(f'r4-generic-{leg}',
                                               units_text),
                                   f'r4-generic-out-{leg}')
            self.assertEqual(run.returncode, 0,
                             (leg, run.stdout + run.stderr))
            self.assertIn('Report SHA256: ', run.stdout,
                          (leg, run.stdout + run.stderr))
            self.assertEqual(report['status'], 'passed', (leg, report))
            entry = report['packages']['pkg/auth']
            self.assertEqual([(fn['name'], fn['seed'])
                              for fn in entry['functions']],
                             [('Guarded', True)], (leg, entry))
            evidence = report['selector']['evidence']['pkg/auth']
            self.assertIsNone(evidence['widened'], (leg, evidence))
            self.assertEqual(
                evidence['reasons'],
                {'Guarded': ['changed test target: TestGenericMethod']},
                (leg, evidence))
            self.assertEqual(evidence['rebaselined'],
                             ['TestGenericMethod \u2192 Guarded'],
                             (leg, evidence))

    def test_r4_receiver_distinct_helpers_bind_own_targets(self):
        """EXT-RECV-01: two receiver-distinct helper methods of the
        checked external test group — alpha.allow reaching Allowed and
        beta.allow reaching Denied, with beta never invoked — are two
        identities, never one bare allow name. A test-only edit of the
        alpha caller selects exactly Allowed and re-baselines exactly
        that binding; the frozen original pair and the isolated
        bare-emission splice select Denied too under the same
        changed-target reason yet still pass, because the base suite
        never executed beta.allow — the silent misattribution this
        correction removes. Independent coverage facts come from go
        test profiles parsed by execution counts."""
        module = self.write_module('fnrecv', {
            'pkg/auth/auth.go': ('package auth\n\n'
                                 'func Allowed(n int) bool { return n > 0 }\n\n'
                                 'func Denied(n int) bool { return false }\n'),
            'pkg/auth/receiver_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/fnrecv/pkg/auth"\n)\n\n'
                'type alpha struct{}\n\ntype beta struct{}\n\n'
                'func (alpha) allow() bool {\n'
                '\treturn auth.Allowed(1)\n}\n\n'
                'func (beta) allow() bool {\n'
                '\treturn auth.Denied(1)\n}\n\n'
                'func TestAlpha(t *testing.T) {\n'
                '\tif !(alpha{}).allow() {\n'
                '\t\tt.Fatal("alpha helper must execute")\n'
                '\t}\n}\n'),
        })
        original_units = frozen_blob('r4_units')
        original_conservative = frozen_blob('r4_conservative')
        current_units = self.helper.read_text()
        isolated_units = current_units.replace(
             'd.refs[key] = true',
             '_ = key\n'
             '\t\td.refs[obj.Origin().Name()] = true\n'
             '\t\td.floorRefs[obj.Origin().Name()] = true')
        self.assertNotEqual(isolated_units, current_units)
        original_path = self.root / 'r4-recv-original-units.go'
        isolated_path = self.root / 'r4-recv-isolated-units.go'
        original_path.write_text(original_units)
        isolated_path.write_text(isolated_units)
        paths = ['pkg/auth/auth.go', 'pkg/auth/receiver_test.go']
        for leg, helper in (('fixed', self.helper), ('original', original_path),
                            ('isolated', isolated_path)):
            rows = self.run_units(module, paths, [[]], helper=helper)
            caller = self.unit(rows['pkg/auth/receiver_test.go'], 'TestAlpha')
            alpha = self.unit(rows['pkg/auth/receiver_test.go'], 'allow') \
                if leg == 'fixed' else None
            if leg == 'fixed':
                # Receiver-qualified key: alpha.allow reaches the alpha
                # twin only, and beta.allow stays a foreign spelling.
                self.assertEqual(sorted(caller.get('refs') or []),
                                 ['alpha', 'alpha.allow', 'testing'], caller)
                self.assertEqual(caller.get('selrefs') or [], [], caller)
                twins = [u for u in rows['pkg/auth/receiver_test.go']['units']
                         if u['name'] == 'allow']
                self.assertEqual(sorted(u.get('recv') for u in twins),
                                 ['alpha', 'beta'], twins)
                by_recv = {u.get('recv'): u for u in twins}
                # Method rows keep the receiver type itself in refs,
                # exactly like fnmeth's probe assertion.
                self.assertEqual(sorted(by_recv['alpha'].get('refs') or []),
                                 ['Allowed', 'alpha', 'auth'],
                                 by_recv['alpha'])
                self.assertEqual(sorted(by_recv['beta'].get('refs') or []),
                                 ['Denied', 'auth', 'beta'],
                                 by_recv['beta'])
            else:
                # Original and isolated: bare allow erases the receiver,
                # so one name stands for both twins.
                self.assertEqual(sorted(caller.get('refs') or []),
                                 ['allow', 'alpha', 'testing'], (leg, caller))
                self.assertNotIn('alpha.allow',
                                 (caller.get('refs') or []) +
                                 (caller.get('selrefs') or []),
                                 (leg, caller))
            self.assertEqual(
                rows['pkg/auth/receiver_test.go'].get('resolution') or [], [],
                (leg, rows['pkg/auth/receiver_test.go'].get('resolution')))
        testfile = module / 'pkg/auth/receiver_test.go'
        intact = testfile.read_text()
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        env = self.go_env(**{critical_scope.MODE_ENV: critical_scope.CONSERVATIVE})
        profile = self.root / 'r4-recv-cover'

        def covered_lines(tag):
            run = subprocess.run(
                ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
                cwd=module, capture_output=True, text=True, env=env,
                timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            counts = {}
            for line in profile.read_text().splitlines():
                if not line or line.startswith('mode:'):
                    continue
                parts = line.split()
                location = parts[0]
                if location.rsplit('/', 1)[-1].split(':')[0] != 'auth.go':
                    continue
                start = int(location.rsplit(':', 1)[1].split('.')[0])
                counts[start] = max(counts.get(start, 0), int(parts[-1]))
            return counts

        def func_line(name):
            source = (module / 'pkg/auth/auth.go').read_text()
            return next(index + 1 for index, text_line
                        in enumerate(source.splitlines())
                        if text_line.startswith(f'func {name}'))

        allowed_line = func_line('Allowed')
        denied_line = func_line('Denied')
        counts = covered_lines('base')
        self.assertGreaterEqual(counts[allowed_line], 1,
                                'base never executed Allowed')
        self.assertEqual(counts.get(denied_line, 0), 0,
                         'base executed Denied without any beta caller')
        # Test-only fingerprint edit: only TestAlpha's body hash moves.
        testfile.write_text(intact.replace(
            'alpha helper must execute',
            'alpha helper must still execute'))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'test-only fingerprint edit']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')

        def shadow_gate(name, units_text, conservative_text=None):
            directory = self.root / name / 'go_policy'
            directory.mkdir(parents=True)
            for item in Path(critical_conservative.__file__).parent.iterdir():
                if item.suffix == '.py' or item.name == 'critical.json':
                    shutil.copyfile(item, directory / item.name)
            (directory / 'units.go').write_text(units_text)
            if conservative_text is not None:
                (directory / 'critical_conservative.py').write_text(
                    conservative_text)
            return directory / 'critical.py'

        def run_gate(cli, out_name):
            out = self.root / out_name
            if out.exists():
                shutil.rmtree(out)
            run = subprocess.run(
                [sys.executable, str(cli), '--root', str(module),
                 '--base', base, '--gremlins', gremlins,
                 '--output', str(out)],
                cwd=self.root, capture_output=True, text=True, env=env,
                timeout=600)
            report_path = out / 'report.json'
            report = (json.loads(report_path.read_text())
                      if report_path.exists() else {})
            return run, report

        # Fixed: exactly Allowed is selected, re-baselined and seeded.
        run, report = run_gate(
            Path(critical_conservative.__file__).parent / 'critical.py',
            'r4-recv-out-fixed')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('Report SHA256: ', run.stdout, run.stdout + run.stderr)
        self.assertEqual(report['status'], 'passed', report)
        entry = report['packages']['pkg/auth']
        self.assertEqual([(fn['name'], fn['seed']) for fn in entry['functions']],
                         [('Allowed', True)], entry)
        evidence = report['selector']['evidence']['pkg/auth']
        self.assertIsNone(evidence['widened'], evidence)
        self.assertEqual(evidence['reasons'],
                         {'Allowed': ['changed test target: TestAlpha']},
                         evidence)
        self.assertEqual(evidence['rebaselined'],
                         ['TestAlpha \u2192 Allowed'], evidence)
        # Original pair and isolated bare-emission splice: the bare
        # name reaches both twins, so Denied inherits the alpha edit's
        # reason and selection while the never-covered beta binding
        # drops as a vacuous like-name collision — the gate stays green.
        for leg, units_text, conservative_text in (
                ('original', original_units, original_conservative),
                ('isolated', isolated_units, None)):
            run, report = run_gate(
                shadow_gate(f'r4-recv-{leg}', units_text, conservative_text),
                f'r4-recv-out-{leg}')
            self.assertEqual(run.returncode, 0,
                             (leg, run.stdout + run.stderr))
            self.assertIn('Report SHA256: ', run.stdout,
                          (leg, run.stdout + run.stderr))
            self.assertEqual(report['status'], 'passed', (leg, report))
            entry = report['packages']['pkg/auth']
            self.assertEqual({(fn['name'], fn['seed'])
                              for fn in entry['functions']},
                             {('Allowed', True), ('Denied', True)},
                             (leg, entry))
            evidence = report['selector']['evidence']['pkg/auth']
            self.assertIsNone(evidence['widened'], (leg, evidence))
            self.assertEqual(
                evidence['reasons'],
                {'Allowed': ['changed test target: TestAlpha'],
                 'Denied': ['changed test target: TestAlpha']},
                (leg, evidence))
            self.assertEqual(evidence['rebaselined'],
                             ['TestAlpha \u2192 Allowed'], (leg, evidence))

    def test_r4_dynamic_baseline_dispatch_queues_lost_coverage(self):
        """LOST-SELREF-01: a baseline helper that dispatched through a
        func-typed field — holder.Allowed wired to production Allowed —
        kept that function covered at the base. When the rewrite drops
        only the helper invocation, the current target's closure is
        clean, so only the baseline walk still sees the selref; the
        fixed gate treats it as a real obligation, widens for the
        unresolved production dispatch and blocks with a named
        lost_unit_coverage error. The frozen original pair and the
        isolated dynamic-set splice drop that obligation instead and
        pass green while Allowed is independently uncovered. Coverage
        facts come from go test profiles parsed by execution counts."""
        module = self.write_module('fndyn', {
            'pkg/auth/auth.go': ('package auth\n\n'
                                 'func Allowed(n int) bool { return n > 0 }\n\n'
                                 'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/holder/holder.go': (
                'package holder\n\n'
                'import "example.test/fndyn/pkg/auth"\n\n'
                'type Holder struct{ Allowed func(int) bool }\n\n'
                'func New() Holder {\n'
                '\treturn Holder{Allowed: auth.Allowed}\n}\n'),
            'pkg/auth/dynamic_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/fndyn/pkg/auth"\n\n'
                '\t"example.test/fndyn/pkg/holder"\n)\n\n'
                'func helperAllowed(h holder.Holder) bool {\n'
                '\treturn h.Allowed(6)\n}\n\n'
                'func TestBothPaths(t *testing.T) {\n'
                '\tif !helperAllowed(holder.New()) {\n'
                '\t\tt.Fatal("helper dynamic dispatch must execute")\n'
                '\t}\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("direct production call must execute")\n'
                '\t}\n}\n'),
        })
        testfile = module / 'pkg/auth/dynamic_test.go'
        intact = testfile.read_text()
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        env = self.go_env(**{critical_scope.MODE_ENV: critical_scope.CONSERVATIVE})
        profile = self.root / 'r4-dyn-cover'

        def covered_lines():
            run = subprocess.run(
                ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
                cwd=module, capture_output=True, text=True, env=env,
                timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            counts = {}
            for line in profile.read_text().splitlines():
                if not line or line.startswith('mode:'):
                    continue
                parts = line.split()
                location = parts[0]
                if location.rsplit('/', 1)[-1].split(':')[0] != 'auth.go':
                    continue
                start = int(location.rsplit(':', 1)[1].split('.')[0])
                counts[start] = max(counts.get(start, 0), int(parts[-1]))
            return counts

        def func_line(name):
            source = (module / 'pkg/auth/auth.go').read_text()
            return next(index + 1 for index, text_line
                        in enumerate(source.splitlines())
                        if text_line.startswith(f'func {name}'))

        allowed_line, guarded_line = func_line('Allowed'), func_line('Guarded')
        counts = covered_lines()
        self.assertGreaterEqual(counts[allowed_line], 1,
                                'base never executed Allowed')
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'base never executed Guarded')
        # Rewrite: drop ONLY the helper invocation; the helper itself
        # stays byte-identical and the direct Guarded call keeps the
        # test green.
        testfile.write_text(intact.replace(
            '\tif !helperAllowed(holder.New()) {\n'
            '\t\tt.Fatal("helper dynamic dispatch must execute")\n\t}\n', ''))
        rewritten = testfile.read_text()
        self.assertIn('func helperAllowed(h holder.Holder) bool', rewritten)
        self.assertNotIn('helperAllowed(', rewritten.replace(
            'func helperAllowed(h holder.Holder) bool', ''))
        self.assertIn('auth.Guarded(2)', rewritten)
        for argv in (['add', '.'],
                      ['-c', 'user.name=Fixture',
                       '-c', 'user.email=fixture@example.invalid',
                       'commit', '-qm', 'drop dynamic helper invocation only']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        counts = covered_lines()
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'rewrite no longer executes Guarded')
        self.assertEqual(counts.get(allowed_line, 0), 0,
                         'rewrite still executes Allowed')
        # Fixed gate, direct selection first: critical.py computes this
        # selection before it creates any report, so the CLI leg below
        # can never carry report fields — the raise itself and the CLI
        # error text are the evidence.
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV,
                            critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            with self.assertRaises(ValueError) as caught:
                critical_scope.targets(
                    module, base, {'critical_paths': ['pkg/auth/**']})
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertIn('lost_unit_coverage', str(caught.exception),
                      caught.exception)
        self.assertIn('TestBothPaths no longer exercises Allowed',
                      str(caught.exception), caught.exception)
        original_units = frozen_blob('r4_units')
        original_conservative = frozen_blob('r4_conservative')
        current_conservative = Path(critical_conservative.__file__).read_text()
        isolated_conservative = current_conservative.replace(
            'dynamic = resolve_production(selrefs & names, selrefs & names, [previous])',
            'dynamic = set()')
        self.assertNotEqual(isolated_conservative, current_conservative)
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')

        def shadow_gate(name, units_text, conservative_text=None):
            directory = self.root / name / 'go_policy'
            directory.mkdir(parents=True)
            for item in Path(critical_conservative.__file__).parent.iterdir():
                if item.suffix == '.py' or item.name == 'critical.json':
                    shutil.copyfile(item, directory / item.name)
            (directory / 'units.go').write_text(units_text)
            if conservative_text is not None:
                (directory / 'critical_conservative.py').write_text(
                    conservative_text)
            return directory / 'critical.py'

        def run_gate(cli, out_name):
            out = self.root / out_name
            if out.exists():
                shutil.rmtree(out)
            run = subprocess.run(
                [sys.executable, str(cli), '--root', str(module),
                 '--base', base, '--gremlins', gremlins,
                 '--output', str(out)],
                cwd=self.root, capture_output=True, text=True, env=env,
                timeout=600)
            report_path = out / 'report.json'
            report = (json.loads(report_path.read_text())
                      if report_path.exists() else {})
            return run, report

        # Fixed production gate: the raise happens inside the early
        # targets() computation, before critical.py creates or writes
        # any report — rc=2 with the exact error text and NO report
        # file. Absence is asserted explicitly: never an invented
        # failed report, never a pass.
        run, report = run_gate(
            Path(critical_conservative.__file__).parent / 'critical.py',
            'r4-dyn-out-fixed')
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertIn('lost_unit_coverage: pkg/auth: TestBothPaths no '
                      'longer exercises Allowed', run.stdout + run.stderr)
        self.assertEqual(report, {})
        self.assertFalse(
            (self.root / 'r4-dyn-out-fixed' / 'report.json').exists(),
            'early selection rejection must not write a report')
        # Original pair and isolated dynamic-set splice: the selref
        # obligation is dropped — green gate, independently uncovered
        # Allowed, the end-to-end silent-loss negative.
        for leg, conservative_text in (
                ('original', original_conservative),
                ('isolated', isolated_conservative)):
            run, report = run_gate(
                shadow_gate(f'r4-dyn-{leg}', original_units
                            if leg == 'original' else self.helper.read_text(),
                            conservative_text),
                f'r4-dyn-out-{leg}')
            self.assertEqual(run.returncode, 0,
                             (leg, run.stdout + run.stderr))
            self.assertIn('Report SHA256: ', run.stdout,
                          (leg, run.stdout + run.stderr))
            self.assertEqual(report['status'], 'passed', (leg, report))
            entry = report['packages']['pkg/auth']
            self.assertEqual([(fn['name'], fn['seed'])
                              for fn in entry['functions']],
                             [('Guarded', True)], (leg, entry))
            evidence = report['selector']['evidence']['pkg/auth']
            self.assertIsNone(evidence['widened'], (leg, evidence))
            self.assertEqual(
                evidence['reasons'],
                {'Guarded': ['changed test target: TestBothPaths']},
                (leg, evidence))
            self.assertEqual(evidence['rebaselined'],
                             ['TestBothPaths \u2192 Guarded'], (leg, evidence))

    # --- R5 selector-owner correction controls ---------------------------
    # Six controls pin the confirmed selector findings on this tree:
    # transitive dynamic closure (F1), removed-unit baseline
    # obligations (F2), obligate indirect dispatch (F3), global-state
    # spellings through the production closure (F4), same-name caller
    # projection and bare helper identity (F5), and floor_refs
    # spellings (F6, with the deadline controls). Gate-level tests
    # follow the established r4 pattern: a real module, a real
    # base/rewrite git cycle, an independent go-test coverage oracle,
    # and fixed + original + isolated legs whose expectations come from
    # measured runs, never from the implementation under test.

    def r4_original_pair(self):
        """The frozen original helper and conservative module texts,
        verified byte-for-byte against the recorded base blobs."""
        return frozen_blob('r4_units'), frozen_blob('r4_conservative')

    def r4_shadow_gate(self, name, units_text, conservative_text=None):
        """A complete go_policy shadow tree with a substituted helper
        and/or conservative module; returns the shadow critical.py."""
        directory = self.root / name / 'go_policy'
        directory.mkdir(parents=True)
        for item in Path(critical_conservative.__file__).parent.iterdir():
            if item.suffix == '.py' or item.name == 'critical.json':
                shutil.copyfile(item, directory / item.name)
        (directory / 'units.go').write_text(units_text)
        if conservative_text is not None:
            (directory / 'critical_conservative.py').write_text(
                conservative_text)
        return directory / 'critical.py'

    def r4_run_gate(self, cli, module, base, env, gremlins, out_name):
        """One real gate CLI run; returns the process and its report,
        absent when the gate rejected the selection before reporting."""
        out = self.root / out_name
        if out.exists():
            shutil.rmtree(out)
        run = subprocess.run(
            [sys.executable, str(cli), '--root', str(module),
             '--base', base, '--gremlins', gremlins,
             '--output', str(out)],
            cwd=self.root, capture_output=True, text=True, env=env,
            timeout=600)
        report_path = out / 'report.json'
        report = (json.loads(report_path.read_text())
                  if report_path.exists() else {})
        return run, report

    def test_r4_lost_unit_dynamic_closure_transitively_binds_factory(self):
        """R5-F1: a baseline test that reached a production factory
        through a func-typed field owes the factory's whole transitive
        body closure, not just the field spelling. Dropping the helper
        invocation loses Leaf — reached only through
        support.Factory().Allowed()() — and the fixed gate must block
        with lost_unit_coverage naming Leaf. Appending the selref
        spelling after the closure misses Leaf: the original pair and
        the dynamic-set splice both stay green with independently
        uncovered Leaf, the end-to-end silent-loss negative."""
        module = self.write_module('r4f1dyn', {
            'pkg/auth/auth.go': (
                'package auth\n\n'
                'func Leaf() bool { return true }\n\n'
                'func Allowed() func() bool { return Leaf }\n\n'
                'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/support/support.go': (
                'package support\n\n'
                'import "example.test/r4f1dyn/pkg/auth"\n\n'
                'type Handler struct{ Allowed func() func() bool }\n\n'
                'func Factory() Handler {\n'
                '\treturn Handler{Allowed: auth.Allowed}\n}\n'),
            'pkg/auth/dynamic_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/r4f1dyn/pkg/auth"\n\n'
                '\t"example.test/r4f1dyn/pkg/support"\n)\n\n'
                'func helperDynamic() bool {\n'
                '\treturn support.Factory().Allowed()()\n}\n\n'
                'func TestBothPaths(t *testing.T) {\n'
                '\tif !helperDynamic() {\n'
                '\t\tt.Fatal("dynamic factory dispatch must execute")\n'
                '\t}\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("direct production call must execute")\n'
                '\t}\n}\n\n'
                'func TestAllowedOnly(t *testing.T) {\n'
                '\tif _ = auth.Allowed(); false {\n'
                '\t\tt.Fatal("unreachable")\n'
                '\t}\n}\n'),
        })
        testfile = module / 'pkg/auth/dynamic_test.go'
        intact = testfile.read_text()
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        env = self.go_env(**{critical_scope.MODE_ENV: critical_scope.CONSERVATIVE})
        profile = self.root / 'r4-f1-cover'

        def covered_lines():
            run = subprocess.run(
                ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
                cwd=module, capture_output=True, text=True, env=env,
                timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            counts = {}
            for line in profile.read_text().splitlines():
                if not line or line.startswith('mode:'):
                    continue
                parts = line.split()
                location = parts[0]
                if location.rsplit('/', 1)[-1].split(':')[0] != 'auth.go':
                    continue
                start = int(location.rsplit(':', 1)[1].split('.')[0])
                counts[start] = max(counts.get(start, 0), int(parts[-1]))
            return counts

        def func_line(name):
            source = (module / 'pkg/auth/auth.go').read_text()
            return next(index + 1 for index, text_line
                        in enumerate(source.splitlines())
                        if text_line.startswith(f'func {name}'))

        leaf_line = func_line('Leaf')
        allowed_line = func_line('Allowed')
        guarded_line = func_line('Guarded')
        counts = covered_lines()
        self.assertGreaterEqual(counts[leaf_line], 1,
                                'base never executed Leaf')
        self.assertGreaterEqual(counts[allowed_line], 1,
                                'base never executed Allowed')
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'base never executed Guarded')
        # Rewrite: drop ONLY the helper invocation; the helper stays
        # byte-identical and TestAllowedOnly keeps executing Allowed
        # without ever calling the returned factory closure.
        testfile.write_text(intact.replace(
            '\tif !helperDynamic() {\n'
            '\t\tt.Fatal("dynamic factory dispatch must execute")\n\t}\n',
            ''))
        rewritten = testfile.read_text()
        self.assertIn('func helperDynamic() bool', rewritten)
        self.assertNotIn('helperDynamic(', rewritten.replace(
            'func helperDynamic() bool', ''))
        self.assertIn('auth.Guarded(2)', rewritten)
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'drop dynamic helper invocation only']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        counts = covered_lines()
        self.assertEqual(counts.get(leaf_line, 0), 0,
                         'rewrite still executes Leaf')
        self.assertGreaterEqual(counts[allowed_line], 1,
                                'rewrite lost Allowed outside the helper')
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'rewrite no longer executes Guarded')
        # Fixed gate, direct selection first: the raise happens inside
        # the early targets() computation, before any report exists.
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV,
                            critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            with self.assertRaises(ValueError) as caught:
                critical_scope.targets(
                    module, base, {'critical_paths': ['pkg/auth/**']})
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertIn('lost_unit_coverage', str(caught.exception),
                      caught.exception)
        self.assertIn('TestBothPaths no longer exercises Leaf',
                      str(caught.exception), caught.exception)
        original_units, original_conservative = self.r4_original_pair()
        current_conservative = Path(critical_conservative.__file__).read_text()
        isolated_conservative = current_conservative.replace(
            'dynamic = resolve_production(selrefs & names, selrefs & names,'
            ' [previous])', 'dynamic = set()')
        self.assertNotEqual(isolated_conservative, current_conservative)
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')
        run, report = self.r4_run_gate(
            Path(critical_conservative.__file__).parent / 'critical.py',
            module, base, env, gremlins, 'r4-f1-out-fixed')
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertIn('lost_unit_coverage: pkg/auth: TestBothPaths no '
                      'longer exercises Leaf', run.stdout + run.stderr)
        self.assertEqual(report, {})
        self.assertFalse(
            (self.root / 'r4-f1-out-fixed' / 'report.json').exists(),
            'early selection rejection must not write a report')
        for leg, units_text, conservative_text in (
                ('original', original_units, original_conservative),
                ('isolated', self.helper.read_text(),
                 isolated_conservative)):
            run, report = self.r4_run_gate(
                self.r4_shadow_gate(f'r4-f1-{leg}', units_text,
                                    conservative_text),
                module, base, env, gremlins, f'r4-f1-out-{leg}')
            self.assertEqual(run.returncode, 0,
                             (leg, run.stdout + run.stderr))
            self.assertIn('Report SHA256: ', run.stdout,
                          (leg, run.stdout + run.stderr))
            self.assertEqual(report['status'], 'passed', (leg, report))
            entry = report['packages']['pkg/auth']
            self.assertEqual([(fn['name'], fn['seed'])
                              for fn in entry['functions']],
                             [('Guarded', True)], (leg, entry))
            evidence = report['selector']['evidence']['pkg/auth']
            self.assertIsNone(evidence['widened'], (leg, evidence))
            self.assertEqual(
                evidence['reasons'],
                {'Guarded': ['changed test target: TestBothPaths']},
                (leg, evidence))
            self.assertEqual(evidence['rebaselined'],
                             ['TestBothPaths \u2192 Guarded'], (leg, evidence))

    def test_r4_removed_unit_closure_blocks_baseline_loss(self):
        """R5-F2: removing a test file removes its helpers with it, and
        a removed helper that reached production through a func-typed
        field (h.Allowed(6)) carries a baseline selref obligation, not
        a widening. The fixed gate must block with lost_unit_coverage
        naming the function the removed test alone used to cover. The
        original pair and the dynamic-set splice drop the selref and
        stay green — widen-without-consumer, silently lost Allowed."""
        module = self.write_module('r4f2rm', {
            'pkg/auth/auth.go': (
                'package auth\n\n'
                'func Allowed(n int) bool { return n > 0 }\n\n'
                'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/holder/holder.go': (
                'package holder\n\n'
                'import "example.test/r4f2rm/pkg/auth"\n\n'
                'type Holder struct{ Allowed func(int) bool }\n\n'
                'func New() Holder {\n'
                '\treturn Holder{Allowed: auth.Allowed}\n}\n'),
            'pkg/auth/guarded_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/r4f2rm/pkg/auth"\n)\n\n'
                'func TestGuardedOnly(t *testing.T) {\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("guarded must execute")\n'
                '\t}\n}\n'),
            'pkg/auth/dynamic_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/r4f2rm/pkg/auth"\n\n'
                '\t"example.test/r4f2rm/pkg/holder"\n)\n\n'
                'func helperAllowed(h holder.Holder) bool {\n'
                '\treturn h.Allowed(6)\n}\n\n'
                'func TestBothPaths(t *testing.T) {\n'
                '\tif !helperAllowed(holder.New()) {\n'
                '\t\tt.Fatal("helper dynamic dispatch must execute")\n'
                '\t}\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("direct production call must execute")\n'
                '\t}\n}\n'),
        })
        removed = module / 'pkg/auth/dynamic_test.go'
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        env = self.go_env(**{critical_scope.MODE_ENV: critical_scope.CONSERVATIVE})
        profile = self.root / 'r4-f2-cover'

        def covered_lines():
            run = subprocess.run(
                ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
                cwd=module, capture_output=True, text=True, env=env,
                timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            counts = {}
            for line in profile.read_text().splitlines():
                if not line or line.startswith('mode:'):
                    continue
                parts = line.split()
                location = parts[0]
                if location.rsplit('/', 1)[-1].split(':')[0] != 'auth.go':
                    continue
                start = int(location.rsplit(':', 1)[1].split('.')[0])
                counts[start] = max(counts.get(start, 0), int(parts[-1]))
            return counts

        def func_line(name):
            source = (module / 'pkg/auth/auth.go').read_text()
            return next(index + 1 for index, text_line
                        in enumerate(source.splitlines())
                        if text_line.startswith(f'func {name}'))

        allowed_line = func_line('Allowed')
        guarded_line = func_line('Guarded')
        counts = covered_lines()
        self.assertGreaterEqual(counts[allowed_line], 1,
                                'base never executed Allowed')
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'base never executed Guarded')
        # Rewrite: remove the whole dynamic dispatch test file; the
        # guarded-only twin survives and keeps the gate's suite green.
        removed.unlink()
        for argv in (['add', '-A'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'remove dynamic dispatch tests']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        counts = covered_lines()
        self.assertEqual(counts.get(allowed_line, 0), 0,
                         'surviving suite still executes Allowed')
        self.assertGreaterEqual(counts[guarded_line], 1,
                                'rewrite no longer executes Guarded')
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV,
                            critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            with self.assertRaises(ValueError) as caught:
                critical_scope.targets(
                    module, base, {'critical_paths': ['pkg/auth/**']})
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertIn('lost_unit_coverage', str(caught.exception),
                      caught.exception)
        self.assertIn('helperAllowed no longer exercises Allowed',
                      str(caught.exception), caught.exception)
        original_units, original_conservative = self.r4_original_pair()
        current_conservative = Path(critical_conservative.__file__).read_text()
        isolated_conservative = current_conservative.replace(
            'dynamic = resolve_production(selrefs & names, selrefs & names,'
            ' [previous])', 'dynamic = set()')
        self.assertNotEqual(isolated_conservative, current_conservative)
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')
        run, report = self.r4_run_gate(
            Path(critical_conservative.__file__).parent / 'critical.py',
            module, base, env, gremlins, 'r4-f2-out-fixed')
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        # Both removed obligations queue Allowed and both are lost; the
        # message sorts by obligation identity, so TestBothPaths leads.
        self.assertIn('lost_unit_coverage: pkg/auth: TestBothPaths no '
                      'longer exercises Allowed', run.stdout + run.stderr)
        self.assertIn('helperAllowed no longer exercises Allowed',
                      run.stdout + run.stderr)
        self.assertEqual(report, {})
        self.assertFalse(
            (self.root / 'r4-f2-out-fixed' / 'report.json').exists(),
            'early selection rejection must not write a report')
        for leg, units_text, conservative_text in (
                ('original', original_units, original_conservative),
                ('isolated', self.helper.read_text(),
                 isolated_conservative)):
            run, report = self.r4_run_gate(
                self.r4_shadow_gate(f'r4-f2-{leg}', units_text,
                                    conservative_text),
                module, base, env, gremlins, f'r4-f2-out-{leg}')
            self.assertEqual(run.returncode, 0,
                             (leg, run.stdout + run.stderr))
            self.assertIn('Report SHA256: ', run.stdout,
                          (leg, run.stdout + run.stderr))
            self.assertEqual(report['status'], 'passed', (leg, report))
            entry = report['packages']['pkg/auth']
            self.assertEqual({(fn['name'], fn['seed'])
                              for fn in entry['functions']},
                             {('Allowed', True), ('Guarded', True)},
                             (leg, entry))
            evidence = report['selector']['evidence']['pkg/auth']
            self.assertEqual(evidence['widened'],
                             ['removed test target without bindable '
                              'consumer: helperAllowed'], (leg, evidence))
            self.assertEqual(
                evidence['reasons'],
                {'Guarded': ['removed test coverage: TestBothPaths'],
                 '*': ['removed test target without bindable consumer: '
                       'helperAllowed']},
                (leg, evidence))
            self.assertEqual(evidence['rebaselined'],
                             ['TestBothPaths \u2192 Guarded'], (leg, evidence))

    A2_AUTH = ('package auth\n\n'
               'func Allowed(n int) bool { return n > 0 }\n\n'
               'func Denied() bool { return false }\n')
    A2_HELPER_BASE = 'func (a A) helper() bool { return Allowed(1) }\n'
    A2_HELPER_EDIT = 'func (a A) helper() bool { return Allowed(2) }\n'

    def test_r4_alias_receiver_helpers_keep_canonical_identity(self):
        """EXT-ALIAS-01 (A2): helper methods declared through an alias
        receiver — value alias A = B and pointer alias A = *B under Go
        1.24+ gotypesalias=1 — must keep the canonical receiver
        identity of their underlying named type, so a test-only edit
        of the aliased helper selects exactly Allowed, its own
        production target. The original pair and the isolated
        alias-spelling splice silently drop the selection entirely
        (no targets, gate not applicable): the checked declaration
        spells A.helper while the call resolves B.helper. Negative
        siblings — the unchanged other.helper twin, the unchanged
        B.steady and pointer-alias pa.idle methods, and the stable
        Denied caller — stay unselected under both edits."""
        value_body = (
            'package auth\n\nimport "testing"\n\n'
            'type B struct{}\n\ntype A = B\n\n' + self.A2_HELPER_BASE +
            'func TestAlias(t *testing.T) {\n'
            '\tif !(B{}).helper() {\n'
            '\t\tt.Fatal("helper must run")\n\t}\n}\n\n'
            'func TestSeparate(t *testing.T) {\n'
            '\tif Denied() {\n'
            '\t\tt.Fatal("denied must not run")\n\t}\n}\n\n'
            'type other int\n\n'
            'func (o other) helper() bool { return false }\n\n'
            'func (b B) steady() bool { return true }\n\n'
            'func TestSteady(t *testing.T) {\n'
            '\tif !(B{}).steady() {\n'
            '\t\tt.Fatal("steady must run")\n\t}\n}\n')
        pointer_body = (
            'package auth\n\nimport "testing"\n\n'
            'type B struct{}\n\ntype A = *B\n\n' + self.A2_HELPER_BASE +
            'func TestAlias(t *testing.T) {\n'
            '\tif !(&B{}).helper() {\n'
            '\t\tt.Fatal("helper must run")\n\t}\n}\n\n'
            'func TestSeparate(t *testing.T) {\n'
            '\tif Denied() {\n'
            '\t\tt.Fatal("denied must not run")\n\t}\n}\n\n'
            'type other int\n\n'
            'func (o other) helper() bool { return false }\n\n'
            'type pa = *other\n\n'
            'func (p pa) idle() bool { return false }\n\n'
            'func TestIdle(t *testing.T) {\n'
            '\to := other(1)\n\tp := pa(&o)\n'
            '\tif p.idle() {\n'
            '\t\tt.Fatal("idle must stay false")\n\t}\n}\n')
        current_units = self.helper.read_text()
        anchor = ('item.Recv = canonicalRecv(res.perDecl[decl], '
                  'receiverName(fn.Recv))')
        self.assertEqual(current_units.count(anchor), 1, anchor)
        isolated_units = current_units.replace(
            anchor, 'item.Recv = receiverName(fn.Recv)')

        def a2_module(name, test_body):
            module = self.write_module(name, {
                'pkg/auth/auth.go': self.A2_AUTH,
                'pkg/auth/alias_test.go': test_body,
            })
            for argv in (['init', '-q'], ['add', '.'],
                         ['-c', 'user.name=Fixture',
                          '-c', 'user.email=fixture@example.invalid',
                          'commit', '-qm', 'base']):
                subprocess.run(['git', *argv], cwd=module, check=True,
                               capture_output=True)
            base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                           cwd=module,
                                           text=True).strip()
            return module, base

        def a2_edit(module, base):
            """One test-only edit: the aliased helper body only."""
            testfile = module / 'pkg/auth/alias_test.go'
            testfile.write_text(
                testfile.read_text().replace(self.A2_HELPER_BASE,
                                             self.A2_HELPER_EDIT))
            for argv in (['add', '.'],
                         ['-c', 'user.name=Fixture',
                          '-c', 'user.email=fixture@example.invalid',
                          'commit', '-qm', 'alias helper body edit only']):
                subprocess.run(['git', *argv], cwd=module, check=True,
                               capture_output=True)
            go = self.go_env()
            run = subprocess.run(['go', 'test', './...'], cwd=module,
                                 capture_output=True, text=True, env=go,
                                 timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            return base

        def a2_scan(module, tag, pointer=False):
            """Three units legs on one fixture: canonical identity in
            the fixed leg, the alias-spelling drop in the other two."""
            paths = ['pkg/auth/auth.go', 'pkg/auth/alias_test.go']
            original_units = frozen_blob('r4_units')
            original_path = self.root / ('a2-%s-original-units.go' % tag)
            isolated_path = self.root / ('a2-%s-isolated-units.go' % tag)
            original_path.write_text(original_units)
            isolated_path.write_text(isolated_units)
            for leg, helper in (('fixed', self.helper),
                                ('original', original_path),
                                ('isolated', isolated_path)):
                rows = self.run_units(module, paths, [[]], helper=helper)
                caller = self.unit(rows['pkg/auth/alias_test.go'], 'TestAlias')
                refs = sorted(caller.get('refs') or [])
                selrefs = caller.get('selrefs') or []
                if leg == 'fixed':
                    # The canonical qualified identity wins for both
                    # alias forms; no alias-spelled or bare key leaks.
                    self.assertIn('B.helper', refs, (tag, leg, caller))
                    self.assertNotIn('A.helper', refs + selrefs,
                                     (tag, leg, caller))
                    self.assertNotIn('helper', refs, (tag, leg, caller))
                    # The unchanged other.helper twin is a different
                    # identity and never answers this caller.
                    self.assertNotIn('other.helper', refs + selrefs,
                                     (tag, leg, caller))
                    self.assertEqual(caller.get('selrefs') or [], [],
                                     (tag, leg, caller))
                    twins = [u for u in
                             rows['pkg/auth/alias_test.go']['units']
                             if u['name'] == 'helper']
                    self.assertEqual(sorted(u.get('recv') for u in twins),
                                     ['B', 'other'], (tag, leg, twins))
                else:
                    twins = [u for u in
                             rows['pkg/auth/alias_test.go']['units']
                             if u['name'] == 'helper']
                    self.assertEqual(sorted(u.get('recv') for u in twins),
                                     ['A', 'other'], (tag, leg, twins))
                    if leg == 'original':
                        # Original pair: the checked declaration is
                        # unknown, so the whole selection drops — not
                        # even the bare floor name survives.
                        self.assertNotIn('B.helper', refs + selrefs,
                                         (tag, leg, caller))
                        self.assertNotIn('helper', refs + selrefs,
                                         (tag, leg, caller))
                    else:
                        # Isolated splice: callers still resolve the
                        # canonical B.helper, but the helper row spells
                        # A.helper — the identity mismatch the consumer
                        # cannot bind (the gate legs below measure the
                        # silent not-applicable red).
                        self.assertIn('B.helper', refs, (tag, leg, caller))
                        self.assertNotIn('A.helper', refs + selrefs,
                                         (tag, leg, caller))
                if not pointer and leg == 'fixed':
                    steady = self.unit(rows['pkg/auth/alias_test.go'],
                                       'TestSteady')
                    self.assertIn('B.steady',
                                  sorted(steady.get('refs') or []),
                                  (tag, leg, steady))
                if pointer and leg == 'fixed':
                    idle = self.unit(rows['pkg/auth/alias_test.go'],
                                     'TestIdle')
                    idle_refs = sorted(idle.get('refs') or [])
                    self.assertIn('other.idle', idle_refs, (tag, leg, idle))
                    self.assertNotIn('pa.idle', idle_refs + selrefs,
                                     (tag, leg, idle))

        env = self.go_env(**{critical_scope.MODE_ENV:
                             critical_scope.CONSERVATIVE})
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')
        cli = Path(critical_conservative.__file__).parent / 'critical.py'
        original_units = frozen_blob('r4_units')
        original_conservative = frozen_blob('r4_conservative')

        def a2_gate(module, base, tag, out_name, units_text=None,
                    conservative_text=None):
            shadow_cli = self.r4_shadow_gate(
                'a2-gate-%s-%s' % (tag, out_name),
                units_text or self.helper.read_text(),
                conservative_text)
            return self.r4_run_gate(shadow_cli, module, base, env,
                                    gremlins,
                                    'a2-out-%s-%s' % (tag, out_name))

        # Value alias: owner red one. Fixed selects exactly Allowed;
        # original pair and isolated splice silently drop the whole
        # selection (not applicable), the red this correction removes.
        module, base = a2_module('a2value', value_body)
        a2_scan(module, 'value')
        base = a2_edit(module, base)
        run, report = a2_gate(module, base, 'value', 'fixed')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('Report SHA256: ', run.stdout, run.stdout + run.stderr)
        self.assertEqual(report['status'], 'passed', report)
        entry = report['packages']['pkg/auth']
        self.assertEqual([(fn['name'], fn['seed']) for fn in
                          entry['functions']], [('Allowed', True)], entry)
        evidence = report['selector']['evidence']['pkg/auth']
        self.assertIsNone(evidence['widened'], evidence)
        self.assertEqual(evidence['reasons'],
                         {'Allowed': ['test helper changed: '
                                      'helper \u2192 TestAlias']}, evidence)
        self.assertEqual(evidence['rebaselined'],
                         ['TestAlias \u2192 Allowed',
                          'helper \u2192 Allowed'], evidence)
        for leg, units_text, conservative_text in (
                ('original', original_units, original_conservative),
                ('isolated', isolated_units, None)):
            run, report = a2_gate(module, base, 'value', leg, units_text,
                                  conservative_text)
            self.assertEqual(run.returncode, 0,
                             (leg, run.stdout + run.stderr))
            self.assertEqual(report['status'], 'not_applicable',
                             (leg, report))
            self.assertNotIn('pkg/auth', report.get('packages') or {},
                             (leg, report))

        # Pointer alias: owner red two. Same expectations, receiver
        # peeled through the alias to its named element type.
        module, base = a2_module('a2ptr', pointer_body)
        a2_scan(module, 'ptr', pointer=True)
        base = a2_edit(module, base)
        run, report = a2_gate(module, base, 'ptr', 'fixed')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('Report SHA256: ', run.stdout, run.stdout + run.stderr)
        self.assertEqual(report['status'], 'passed', report)
        entry = report['packages']['pkg/auth']
        self.assertEqual([(fn['name'], fn['seed']) for fn in
                          entry['functions']], [('Allowed', True)], entry)
        evidence = report['selector']['evidence']['pkg/auth']
        self.assertIsNone(evidence['widened'], evidence)
        self.assertEqual(evidence['reasons'],
                         {'Allowed': ['test helper changed: '
                                      'helper \u2192 TestAlias']}, evidence)
        self.assertEqual(evidence['rebaselined'],
                         ['TestAlias \u2192 Allowed',
                          'helper \u2192 Allowed'], evidence)

    def test_r4_steady_field_dispatch_queues_obligated_coverage(self):
        """R5-F3: an obligated steady body whose indirect dispatch
        crosses a production name must queue its both-side closure, not
        only widen. Rebinding `var check = auth.Allowed` to Guarded
        while the body also calls b.Guarded(2) through a func-typed
        field drops Allowed's coverage; the fixed gate blocks with
        lost_unit_coverage naming TestSteady. The same rebinding
        without the field selector already blocks on both trees
        (direct variant, asserted fixed) and must stay blocked. The
        original pair and the obligated-queue splice stay green on the
        field variant — widening alone, silently lost Allowed."""
        field_module = self.write_module('r4f3field', {
            'pkg/auth/auth.go': (
                'package auth\n\n'
                'func Allowed(n int) bool { return n > 0 }\n\n'
                'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/auth/steady_field_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/r4f3field/pkg/auth"\n)\n\n'
                'type box struct{ Guarded func(int) bool }\n\n'
                'var check = auth.Allowed\n\n'
                'func TestSteady(t *testing.T) {\n'
                '\tb := box{Guarded: auth.Guarded}\n'
                '\tif !check(6) {\n'
                '\t\tt.Fatal("allowed must execute")\n'
                '\t}\n'
                '\tif !b.Guarded(2) {\n'
                '\t\tt.Fatal("guarded must execute")\n'
                '\t}\n}\n'),
        })
        direct_module = self.write_module('r4f3direct', {
            'pkg/auth/auth.go': (
                'package auth\n\n'
                'func Allowed(n int) bool { return n > 0 }\n\n'
                'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/auth/steady_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/r4f3direct/pkg/auth"\n)\n\n'
                'var check = auth.Allowed\n\n'
                'func TestSteady(t *testing.T) {\n'
                '\tif !check(6) {\n'
                '\t\tt.Fatal("allowed must execute")\n'
                '\t}\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("guarded must execute")\n'
                '\t}\n}\n'),
        })
        env = self.go_env(**{critical_scope.MODE_ENV: critical_scope.CONSERVATIVE})
        profile = self.root / 'r4-f3-cover'

        def prepare(module):
            testfile = next(child for child in
                            (module / 'pkg/auth').iterdir()
                            if child.name.endswith('_test.go'))
            intact = testfile.read_text()
            for argv in (['init', '-q'], ['add', '.'],
                         ['-c', 'user.name=Fixture',
                          '-c', 'user.email=fixture@example.invalid',
                          'commit', '-qm', 'base']):
                subprocess.run(['git', *argv], cwd=module, check=True,
                               capture_output=True)
            base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                           cwd=module, text=True).strip()
            return base, testfile, intact

        def rebind(module, prepared, message):
            _, testfile, intact = prepared
            testfile.write_text(intact.replace(
                'var check = auth.Allowed', 'var check = auth.Guarded'))
            self.assertIn('var check = auth.Guarded', testfile.read_text())
            for argv in (['add', '.'],
                         ['-c', 'user.name=Fixture',
                          '-c', 'user.email=fixture@example.invalid',
                          'commit', '-qm', message]):
                subprocess.run(['git', *argv], cwd=module, check=True,
                               capture_output=True)

        def covered_lines(module):
            run = subprocess.run(
                ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
                cwd=module, capture_output=True, text=True, env=env,
                timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            counts = {}
            for line in profile.read_text().splitlines():
                if not line or line.startswith('mode:'):
                    continue
                parts = line.split()
                location = parts[0]
                if location.rsplit('/', 1)[-1].split(':')[0] != 'auth.go':
                    continue
                start = int(location.rsplit(':', 1)[1].split('.')[0])
                counts[start] = max(counts.get(start, 0), int(parts[-1]))
            return counts

        def oracle(module):
            source = (module / 'pkg/auth/auth.go').read_text()
            lines = {}
            for index, text_line in enumerate(source.splitlines()):
                if text_line.startswith('func '):
                    lines[text_line.split()[1].split('(')[0]] = index + 1
            before = covered_lines(module)
            self.assertGreaterEqual(before[lines['Allowed']], 1,
                                    'base never executed Allowed')
            self.assertGreaterEqual(before[lines['Guarded']], 1,
                                    'base never executed Guarded')
            return lines, before

        field_prepared = prepare(field_module)
        direct_prepared = prepare(direct_module)
        field_lines, field_before = oracle(field_module)
        direct_lines, direct_before = oracle(direct_module)
        rebind(field_module, field_prepared, 'rebind check initializer')
        rebind(direct_module, direct_prepared, 'rebind check initializer')
        field_base = field_prepared[0]
        direct_base = direct_prepared[0]
        field_after = covered_lines(field_module)
        self.assertEqual(field_after.get(field_lines['Allowed'], 0), 0,
                         'field rewrite still executes Allowed')
        self.assertGreaterEqual(field_after[field_lines['Guarded']], 1,
                                'field rewrite no longer executes Guarded')
        direct_after = covered_lines(direct_module)
        self.assertEqual(direct_after.get(direct_lines['Allowed'], 0), 0,
                         'direct rewrite still executes Allowed')
        self.assertGreaterEqual(direct_after[direct_lines['Guarded']], 1,
                                'direct rewrite no longer executes Guarded')
        # Direct variant, fixed tree: initializer values are definite
        # references, so the obligate path already blocks here on the
        # unfixed tree too — the correction must never unblock it.
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV,
                            critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            with self.assertRaises(ValueError) as caught:
                critical_scope.targets(
                    field_module, field_base,
                    {'critical_paths': ['pkg/auth/**']})
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertIn('lost_unit_coverage', str(caught.exception),
                      caught.exception)
        self.assertIn('TestSteady no longer exercises Allowed',
                      str(caught.exception), caught.exception)
        original_units, original_conservative = self.r4_original_pair()
        current_conservative = Path(critical_conservative.__file__).read_text()
        isolated_conservative = current_conservative.replace(
            'obligated = current_consumers(effect | dynamic, current)',
            'obligated = []')
        self.assertNotEqual(isolated_conservative, current_conservative)
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')
        run, report = self.r4_run_gate(
            Path(critical_conservative.__file__).parent / 'critical.py',
            field_module, field_base, env, gremlins, 'r4-f3-out-fixed')
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertIn('lost_unit_coverage: pkg/auth: TestSteady no '
                      'longer exercises Allowed', run.stdout + run.stderr)
        self.assertEqual(report, {})
        self.assertFalse(
            (self.root / 'r4-f3-out-fixed' / 'report.json').exists(),
            'early selection rejection must not write a report')
        run, report = self.r4_run_gate(
            Path(critical_conservative.__file__).parent / 'critical.py',
            direct_module, direct_base, env, gremlins, 'r4-f3-out-direct')
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertIn('lost_unit_coverage: pkg/auth: TestSteady no '
                      'longer exercises Allowed', run.stdout + run.stderr)
        self.assertEqual(report, {})
        for leg, units_text, conservative_text in (
                ('original', original_units, original_conservative),
                ('isolated', self.helper.read_text(),
                 isolated_conservative)):
            run, report = self.r4_run_gate(
                self.r4_shadow_gate(f'r4-f3-{leg}', units_text,
                                    conservative_text),
                field_module, field_base, env, gremlins,
                f'r4-f3-out-{leg}')
            self.assertEqual(run.returncode, 0,
                             (leg, run.stdout + run.stderr))
            self.assertIn('Report SHA256: ', run.stdout,
                          (leg, run.stdout + run.stderr))
            self.assertEqual(report['status'], 'passed', (leg, report))
            entry = report['packages']['pkg/auth']
            self.assertEqual({(fn['name'], fn['seed'])
                              for fn in entry['functions']},
                             {('Allowed', True), ('Guarded', True)},
                             (leg, entry))
            evidence = report['selector']['evidence']['pkg/auth']
            self.assertEqual(
                evidence['widened'],
                ['test declaration changed: check \u2192 TestSteady '
                 'references indirect dispatch'], (leg, evidence))
            self.assertEqual(
                evidence['reasons'],
                {'*': ['test declaration changed: check \u2192 TestSteady '
                       'references indirect dispatch']},
                (leg, evidence))
            # The obligate queue never fires on either leg, so the
            # baseline-verification pass is skipped entirely and the
            # rebaselined key is absent from the report.
            self.assertFalse(evidence.get('rebaselined'), (leg, evidence))

    def test_r4_global_state_widen_survives_production_closure(self):
        """R5-F4: a changed test target whose production callee reaches
        package state (var counter) must widen 'references global
        state' — the state spelling reaches the selection only through
        the production body's raw references, so a closure that drops
        them selects the direct callee alone and conceals the global
        read. The isolated raw-set splice reproduces that concealment;
        the original pair already widens."""
        module = self.write_module('r4f4state', {
            'pkg/auth/auth.go': (
                'package auth\n\n'
                'var counter int\n\n'
                'func Guarded(n int) bool {\n'
                '\tcounter++\n'
                '\treturn n > 1\n}\n\n'
                'func Allowed() bool { return true }\n'),
            'pkg/auth/counter_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/r4f4state/pkg/auth"\n)\n\n'
                'func TestCounter(t *testing.T) {\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("guarded must execute")\n'
                '\t}\n}\n'),
        })
        testfile = module / 'pkg/auth/counter_test.go'
        intact = testfile.read_text()
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        env = self.go_env(**{critical_scope.MODE_ENV: critical_scope.CONSERVATIVE})
        profile = self.root / 'r4-f4-cover'
        run = subprocess.run(
            ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
            cwd=module, capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        source = (module / 'pkg/auth/auth.go').read_text()
        guarded_line = next(index + 1 for index, text_line
                            in enumerate(source.splitlines())
                            if text_line.startswith('func Guarded'))
        allowed_line = next(index + 1 for index, text_line
                            in enumerate(source.splitlines())
                            if text_line.startswith('func Allowed'))

        def covered():
            counts = {}
            for line in profile.read_text().splitlines():
                if not line or line.startswith('mode:'):
                    continue
                location = line.split()[0]
                if location.rsplit('/', 1)[-1].split(':')[0] != 'auth.go':
                    continue
                start = int(location.rsplit(':', 1)[1].split('.')[0])
                counts[start] = max(counts.get(start, 0), int(line.split()[-1]))
            return counts

        def guarded_covered():
            return any(guarded_line <= start < allowed_line and count >= 1
                       for start, count in covered().items())

        self.assertTrue(guarded_covered(), 'base never executed Guarded')
        # Test-only fingerprint edit; Guarded stays covered.
        testfile.write_text(intact.replace(
            'guarded must execute', 'guarded must still execute'))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'test-only fingerprint edit']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        run = subprocess.run(
            ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
            cwd=module, capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertTrue(guarded_covered(), 'rewrite no longer executes Guarded')
        original_units, original_conservative = self.r4_original_pair()
        current_conservative = Path(critical_conservative.__file__).read_text()
        isolated_conservative = current_conservative.replace(
            "raw.update(row.get('refs', []))",
            "_ = row.get('refs', [])")
        self.assertNotEqual(isolated_conservative, current_conservative)
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')
        run, report = self.r4_run_gate(
            Path(critical_conservative.__file__).parent / 'critical.py',
            module, base, env, gremlins, 'r4-f4-out-fixed')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('Report SHA256: ', run.stdout, run.stdout + run.stderr)
        self.assertEqual(report['status'], 'passed', report)
        entry = report['packages']['pkg/auth']
        # Functions list in declaration order: Guarded precedes Allowed
        # in auth.go.
        self.assertEqual([(fn['name'], fn['seed'])
                          for fn in entry['functions']],
                         [('Guarded', True), ('Allowed', True)], entry)
        evidence = report['selector']['evidence']['pkg/auth']
        self.assertEqual(evidence['widened'],
                         ['changed test target: TestCounter references '
                          'global state'], evidence)
        # The state widen returns before any per-function binding, so
        # the widened reason alone is recorded; the rebaselined pair
        # comes from the baseline join below.
        self.assertEqual(
            evidence['reasons'],
            {'*': ['changed test target: TestCounter references '
                   'global state']}, evidence)
        self.assertEqual(evidence['rebaselined'],
                         ['TestCounter \u2192 Guarded'], evidence)
        for leg, units_text, conservative_text in (
                ('original', original_units, original_conservative),
                ('isolated', self.helper.read_text(),
                 isolated_conservative)):
            run, report = self.r4_run_gate(
                self.r4_shadow_gate(f'r4-f4-{leg}', units_text,
                                    conservative_text),
                module, base, env, gremlins, f'r4-f4-out-{leg}')
            self.assertEqual(run.returncode, 0,
                             (leg, run.stdout + run.stderr))
            self.assertIn('Report SHA256: ', run.stdout,
                          (leg, run.stdout + run.stderr))
            self.assertEqual(report['status'], 'passed', (leg, report))
            entry = report['packages']['pkg/auth']
            evidence = report['selector']['evidence']['pkg/auth']
            if leg == 'original':
                self.assertEqual(
                    [(fn['name'], fn['seed']) for fn in entry['functions']],
                    [('Guarded', True), ('Allowed', True)],
                    (leg, entry))
                self.assertEqual(
                    evidence['widened'],
                    ['changed test target: TestCounter references '
                     'global state'], (leg, evidence))
                # Same early-return shape as the fixed tree: the widened
                # reason alone, with the baseline join re-baselining
                # TestCounter against Guarded.
                self.assertEqual(
                    evidence['reasons'],
                    {'*': ['changed test target: TestCounter references '
                           'global state']}, (leg, evidence))
            else:
                self.assertEqual(
                    [(fn['name'], fn['seed']) for fn in entry['functions']],
                    [('Guarded', True)], (leg, entry))
                self.assertIsNone(evidence['widened'], (leg, evidence))
                self.assertEqual(
                    evidence['reasons'],
                    {'Guarded': ['changed test target: TestCounter']},
                    (leg, evidence))
            self.assertEqual(evidence['rebaselined'],
                             ['TestCounter \u2192 Guarded'], (leg, evidence))

    def test_r4_reverse_dispatch_callers_projection(self):
        """R5-F5a: same-named method helpers reached through distinct
        receivers must project to exactly their test callers — a
        method helper's own name never enters the test-caller set — and
        an initializer-bound method value must surface the initializer
        test as the changed method's caller. The frozen original pair
        leaks the method name ('step') into the caller set and misses
        the initializer test; both projections are measured through the
        real helper and the real helper_callers on this tree and
        against the shadow original pair."""
        module = self.write_module('r4f5rev', {
            'auth.go': ('package r4f5rev\n\n'
                        'func Allowed() bool { return true }\n'),
            'reverse_test.go': (
                'package r4f5rev_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/r4f5rev"\n)\n\n'
                'func leaf() bool { return r4f5rev.Allowed() }\n\n'
                'type alpha struct{}\n\ntype beta struct{}\n\n'
                'func (alpha) step() bool { return leaf() }\n'
                'func (beta) step() bool { return leaf() }\n\n'
                'func TestAlpha(t *testing.T) {\n'
                '\tif !(alpha{}).step() {\n'
                '\t\tt.Fatal("alpha")\n\t}\n}\n\n'
                'func TestBeta(t *testing.T) {\n'
                '\tif !(beta{}).step() {\n'
                '\t\tt.Fatal("beta")\n\t}\n}\n'),
            'initializer_test.go': (
                'package r4f5rev_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/r4f5rev"\n)\n\n'
                'type gamma struct{}\n\n'
                'func (gamma) step() bool { return r4f5rev.Allowed() }\n\n'
                'var run = (gamma{}).step\n\n'
                'func TestInitializer(t *testing.T) {\n'
                '\tif !run() {\n'
                '\t\tt.Fatal("initializer")\n\t}\n}\n'),
        })
        driver = self.root / 'r4-f5a-driver.py'
        driver.write_text(
            'import inspect\n'
            'import json\n'
            'import os\n'
            'from pathlib import Path\n'
            'import sys\n'
            'sys.path.insert(0, sys.argv[1])\n'
            'import critical_conservative as cc\n'
            "os.environ.update(GOWORK='off', GOFLAGS='',"
            " GOTOOLCHAIN='go1.27.4')\n"
            'root = Path(sys.argv[2])\n'
            'takes_name = list(inspect.signature('
            'cc.helper_callers).parameters)'
            " == ['helper', 'current']\n"
            "rows = cc.unit_rows(root, ['auth.go', 'reverse_test.go'],\n"
            "                    cc.policy.HERE / 'units.go', [''],\n"
            "                    package='.', config={})\n"
            'side = cc.Side(rows, root)\n'
            "leaf = next(unit for unit in side.test_units()"
            " if unit['name'] == 'leaf')\n"
            'affected = cc.helper_callers('
            "leaf['name'] if takes_name else leaf, side)\n"
            "rows = cc.unit_rows(root, ['auth.go', 'initializer_test.go'],\n"
            "                    cc.policy.HERE / 'units.go', [''],\n"
            "                    package='.', config={})\n"
            'side = cc.Side(rows, root)\n'
            "step = next(unit for unit in side.test_units()"
            " if unit['name'] == 'step')\n"
            'initializer = cc.helper_callers('
            "step['name'] if takes_name else step, side)\n"
            "print(json.dumps({'same': sorted(affected),"
            " 'initializer': sorted(initializer)}))\n")
        env = self.go_env()

        def measure(policy_dir):
            run = subprocess.run(
                [sys.executable, str(driver), str(policy_dir), str(module)],
                cwd=self.root, capture_output=True, text=True, env=env,
                timeout=300)
            self.assertEqual(run.returncode, 0, run.stderr[-600:])
            return json.loads(run.stdout)

        current = measure(Path(critical_conservative.__file__).parent)
        self.assertEqual(current['same'], ['TestAlpha', 'TestBeta'], current)
        self.assertEqual(current['initializer'], ['TestInitializer'], current)
        original_units, original_conservative = self.r4_original_pair()
        shadow = self.r4_shadow_gate('r4-f5a-original', original_units,
                                     original_conservative)
        original = measure(shadow.parent)
        self.assertEqual(original['same'],
                         ['TestAlpha', 'TestBeta', 'step'], original)
        self.assertEqual(original['initializer'], [], original)

    def test_r4_bare_helper_twins_bind_own_package_target(self):
        """R5-F5b: a bare package-level helper and a same-named method
        helper are two identities. A test calling the bare helper binds
        exactly the package twin's production target — never the
        method twin's — so a test-only edit of the bare caller selects
        exactly Allowed. The frozen original pair fans the bare name
        across both twins and misattributes Denied to this caller; the
        declaration splice instead removes the group's identity binding,
        so the bare caller loses its bindable consumer entirely and
        widens — the binding this identity keeps narrow."""
        module = self.write_module('r4f5bare', {
            'pkg/auth/auth.go': (
                'package auth\n\n'
                'func Allowed() bool { return true }\n\n'
                'func Denied() bool { return false }\n'),
            'pkg/auth/helpers_test.go': (
                'package auth_test\n\n'
                'import "example.test/r4f5bare/pkg/auth"\n\n'
                'func allow() bool { return auth.Allowed() }\n\n'
                'type beta struct{}\n\n'
                'func (beta) allow() bool { return auth.Denied() }\n'),
            'pkg/auth/caller_test.go': (
                'package auth_test\n\nimport "testing"\n\n'
                'func TestBare(t *testing.T) {\n'
                '\tif !allow() {\n'
                '\t\tt.Fatal("bare allow must execute")\n'
                '\t}\n}\n'),
        })
        # Units-level identity: the bare caller's closure carries the
        # package twin only, and its bindable consumers are exactly
        # Allowed — never the method twin's Denied.
        paths = ['pkg/auth/auth.go', 'pkg/auth/helpers_test.go',
                 'pkg/auth/caller_test.go']
        rows = self.run_units(module, paths, [[]])
        side = critical_conservative.Side(list(rows.values()), module)
        caller = self.unit(rows['pkg/auth/caller_test.go'], 'TestBare')
        refs, floors, selrefs = critical_conservative.target_closure(
            caller, side)
        self.assertEqual(
            sorted(refs), ['Allowed', 'allow', 'auth', 'testing'], refs)
        self.assertNotIn('beta.allow', refs, refs)
        keys = critical_conservative.resolve_production(refs, floors, [side])
        effect, unresolved, raw = critical_conservative.production_closure(
            keys, [side])
        self.assertEqual(raw, set(), 'bare helper closure must carry no raw refs')
        consumers = critical_conservative.current_consumers(effect, side)
        self.assertEqual([row['name'] for row in consumers], ['Allowed'],
                         consumers)
        testfile = module / 'pkg/auth/caller_test.go'
        intact = testfile.read_text()
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        env = self.go_env(**{critical_scope.MODE_ENV: critical_scope.CONSERVATIVE})
        profile = self.root / 'r4-f5b-cover'

        def covered():
            run = subprocess.run(
                ['go', 'test', './pkg/auth', '-coverprofile', str(profile)],
                cwd=module, capture_output=True, text=True, env=env,
                timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            return profile.read_text()

        source = (module / 'pkg/auth/auth.go').read_text()
        allowed_line = next(index + 1 for index, text_line
                            in enumerate(source.splitlines())
                            if text_line.startswith('func Allowed'))
        self.assertIn(f'auth.go:{allowed_line}.', covered(),
                      'base never executed Allowed')
        testfile.write_text(intact.replace(
            'bare allow must execute', 'bare allow must still execute'))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'test-only fingerprint edit']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        self.assertIn(f'auth.go:{allowed_line}.', covered(),
                      'rewrite no longer executes Allowed')
        original_units, original_conservative = self.r4_original_pair()
        current_units = self.helper.read_text()
        isolated_units = current_units.replace(
            'if decls[obj] {', 'if false && decls[obj] {')
        self.assertNotEqual(isolated_units, current_units)
        gremlins = gremlins_binary()
        if not gremlins:
            self.fail('gremlins binary is required for the real gate control')
        run, report = self.r4_run_gate(
            Path(critical_conservative.__file__).parent / 'critical.py',
            module, base, env, gremlins, 'r4-f5b-out-fixed')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('Report SHA256: ', run.stdout, run.stdout + run.stderr)
        self.assertEqual(report['status'], 'passed', report)
        entry = report['packages']['pkg/auth']
        self.assertEqual([(fn['name'], fn['seed'])
                          for fn in entry['functions']],
                         [('Allowed', True)], entry)
        evidence = report['selector']['evidence']['pkg/auth']
        self.assertIsNone(evidence['widened'], evidence)
        self.assertEqual(evidence['reasons'],
                         {'Allowed': ['changed test target: TestBare']},
                         evidence)
        self.assertEqual(evidence['rebaselined'],
                         ['TestBare \u2192 Allowed'], evidence)
        for leg, units_text, conservative_text in (
                ('original', original_units, original_conservative),
                ('isolated', isolated_units, None)):
            run, report = self.r4_run_gate(
                self.r4_shadow_gate(f'r4-f5b-{leg}', units_text,
                                    conservative_text),
                module, base, env, gremlins, f'r4-f5b-out-{leg}')
            self.assertEqual(run.returncode, 0,
                             (leg, run.stdout + run.stderr))
            self.assertIn('Report SHA256: ', run.stdout,
                          (leg, run.stdout + run.stderr))
            self.assertEqual(report['status'], 'passed', (leg, report))
            entry = report['packages']['pkg/auth']
            self.assertEqual({(fn['name'], fn['seed'])
                              for fn in entry['functions']},
                             {('Allowed', True), ('Denied', True)},
                             (leg, entry))
            evidence = report['selector']['evidence']['pkg/auth']
            if leg == 'original':
                # The frozen pair fans the bare name across both twins
                # and misattributes Denied to this caller.
                self.assertIsNone(evidence['widened'], (leg, evidence))
                self.assertEqual(evidence['reasons'],
                                 {'Allowed': ['changed test target: TestBare'],
                                  'Denied': ['changed test target: TestBare']},
                                 (leg, evidence))
                self.assertEqual(evidence['rebaselined'],
                                 ['TestBare \u2192 Allowed'], (leg, evidence))
            else:
                # The splice removes the group's identity binding, so the
                # bare caller loses its bindable consumer entirely and
                # widens instead of misattributing — the binding that
                # identity keeps narrow.
                self.assertEqual(
                    evidence['widened'],
                    ['changed test target: TestBare has no bindable '
                     'production consumer',
                     'lost baseline coverage without bindable consumer: '
                     'TestBare'], (leg, evidence))
                self.assertEqual(evidence['reasons'], {'*': evidence['widened']},
                                 (leg, evidence))
                self.assertNotIn('rebaselined', evidence, (leg, evidence))

    def test_ext01_identity_controls_for_helper_edge(self):
        """EXT-01 identity controls: the bare-identifier helper edge
        binds only a genuine package-level declaration of the checked
        external test package. A local variable shadowing the helper
        name and a foreign package's same-named production function
        create no edge, while the real helper caller and a direct
        production call both keep theirs — exclusion is by object
        identity, never by name."""
        module = self.write_module('fnid', {
            'auth.go': ('package auth\n\n'
                        'func Allowed(n int) bool { return n > 0 }\n\n'
                        'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/other/other.go': ('package other\n\n'
                                   'func Allowed() bool { return true }\n'),
            'identity_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/fnid"\n'
                '\t"example.test/fnid/pkg/other"\n)\n\n'
                'func externalAllowed() bool {\n'
                '\treturn auth.Allowed(6)\n}\n\n'
                'func TestRealHelper(t *testing.T) {\n'
                '\tif !externalAllowed() {\n'
                '\t\tt.Fatal("helper production call must execute")\n'
                '\t}\n}\n\n'
                'func TestLocalShadow(t *testing.T) {\n'
                '\texternalAllowed := func() bool { return true }\n'
                '\tif !externalAllowed() {\n'
                '\t\tt.Fatal("local shadow must execute")\n'
                '\t}\n}\n\n'
                'func TestForeignSpelling(t *testing.T) {\n'
                '\tif !other.Allowed() {\n'
                '\t\tt.Fatal("foreign same-named production symbol must execute")\n'
                '\t}\n}\n\n'
                'func TestGuardedDirect(t *testing.T) {\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("direct production call must execute")\n'
                '\t}\n}\n'),
        })
        rows = self.run_units(module, ['auth.go', 'identity_test.go'], [[]])
        real = self.unit(rows['identity_test.go'], 'TestRealHelper')
        shadow = self.unit(rows['identity_test.go'], 'TestLocalShadow')
        foreign = self.unit(rows['identity_test.go'], 'TestForeignSpelling')
        direct = self.unit(rows['identity_test.go'], 'TestGuardedDirect')
        helper = self.unit(rows['identity_test.go'], 'externalAllowed')
        self.assertEqual(sorted(real.get('refs') or []),
                         ['externalAllowed', 'testing'], real)
        self.assertEqual(sorted(shadow.get('refs') or []),
                         ['testing'], shadow)
        self.assertNotIn('externalAllowed',
                         (shadow.get('refs') or []) + (shadow.get('selrefs') or []),
                         shadow)
        self.assertEqual(sorted(foreign.get('refs') or []),
                         ['other', 'testing'], foreign)
        self.assertNotIn('Allowed',
                         (foreign.get('refs') or []) + (foreign.get('selrefs') or []),
                         foreign)
        self.assertNotIn('externalAllowed',
                         (foreign.get('refs') or []) + (foreign.get('selrefs') or []),
                         foreign)
        self.assertEqual(sorted(direct.get('refs') or []),
                         ['Guarded', 'auth', 'testing'], direct)
        self.assertEqual(sorted(helper.get('refs') or []),
                         ['Allowed', 'auth'], helper)
        for path, out in rows.items():
            self.assertEqual(out.get('resolution') or [], [], (path, out.get('resolution')))

    def test_ext01_cross_file_helper_identity(self):
        """EXT-01 cross-file helper identity: the helper edge survives
        when externalAllowed is a package-level declaration in a
        DIFFERENT _test.go file of the same external test package — the
        source-declaration identity index spans the whole checked group,
        not only the caller's file — and the caller reaches Allowed
        through the helper with no fallback and no direct production
        reference of its own."""
        module = self.write_module('fncrossel', {
            'auth.go': ('package auth\n\n'
                        'func Allowed(n int) bool { return n > 0 }\n'),
            'caller_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n)\n\n'
                'func TestCrossFileHelper(t *testing.T) {\n'
                '\tif externalAllowed(7) != true {\n'
                '\t\tt.Fatal("cross-file helper must execute")\n'
                '\t}\n}\n'),
            'helpers_test.go': (
                'package auth_test\n\nimport (\n'
                '\t"example.test/fncrossel"\n)\n\n'
                'func externalAllowed(seed int) bool {\n'
                '\treturn auth.Allowed(seed)\n}\n'),
        })
        rows = self.run_units(module, ['auth.go', 'caller_test.go',
                                       'helpers_test.go'], [[]])
        caller = self.unit(rows['caller_test.go'], 'TestCrossFileHelper')
        helper = self.unit(rows['helpers_test.go'], 'externalAllowed')
        self.assertEqual(sorted(caller.get('refs') or []),
                         ['externalAllowed', 'testing'], caller)
        self.assertNotIn('Allowed',
                         (caller.get('refs') or []) + (caller.get('selrefs') or []),
                         caller)
        self.assertEqual(sorted(helper.get('refs') or []),
                         ['Allowed', 'auth'], helper)
        for path, out in rows.items():
            self.assertEqual(out.get('resolution') or [], [], (path, out.get('resolution')))

    def test_ext01_external_method_helper_binds_source_declaration(self):
        """EXT-METHOD-01: a concrete method declared on a type of the
        checked external test package is a helper in its own right. Both
        selection forms — the method value (probe{}).allow and the direct
        call probe{}.allow() — bind the method's own declaration by
        object identity through the group's Defs index, never by name:
        the caller reaches Allowed only through the helper with clean
        resolution and no direct production reference of its own."""
        module = self.write_module('fnmeth', {
            'pkg/auth/auth.go': ('package auth\n\n'
                                 'func Allowed(n int) bool { return n > 0 }\n\n'
                                 'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/auth/method_helper_test.go': (
                'package auth_test\n\nimport (\n'
                '\t"example.test/fnmeth/pkg/auth"\n)\n\n'
                'type probe struct{}\n\n'
                'func (p probe) allow() bool {\n'
                '\treturn auth.Allowed(6)\n}\n'),
            'pkg/auth/method_caller_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/fnmeth/pkg/auth"\n)\n\n'
                'func TestMethodHelper(t *testing.T) {\n'
                '\tif fn := (probe{}).allow; !fn() {\n'
                '\t\tt.Fatal("method helper must execute")\n'
                '\t}\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("direct production call must execute")\n'
                '\t}\n}\n\n'
                'func TestDirectMethodCall(t *testing.T) {\n'
                '\tif (probe{}).allow() != true {\n'
                '\t\tt.Fatal("direct method call must execute")\n'
                '\t}\n}\n'),
        })
        rows = self.run_units(module, ['pkg/auth/auth.go',
                                       'pkg/auth/method_helper_test.go',
                                       'pkg/auth/method_caller_test.go'], [[]])
        caller = self.unit(rows['pkg/auth/method_caller_test.go'], 'TestMethodHelper')
        self.assertEqual(sorted(caller.get('refs') or []),
                         ['Guarded', 'auth', 'probe', 'probe.allow',
                          'testing'], caller)
        self.assertEqual(caller.get('selrefs') or [], [], caller)
        direct = self.unit(rows['pkg/auth/method_caller_test.go'],
                           'TestDirectMethodCall')
        self.assertEqual(sorted(direct.get('refs') or []),
                         ['probe', 'probe.allow', 'testing'], direct)
        self.assertNotIn('allow', (direct.get('refs') or []) +
                         (direct.get('selrefs') or []), direct)
        helper = self.unit(rows['pkg/auth/method_helper_test.go'], 'allow')
        self.assertEqual(helper.get('recv'), 'probe', helper)
        self.assertEqual(sorted(helper.get('refs') or []),
                         ['Allowed', 'auth', 'probe'], helper)
        for path in ('pkg/auth/method_helper_test.go',
                     'pkg/auth/method_caller_test.go'):
            self.assertEqual(rows[path].get('resolution') or [], [],
                             (path, rows[path].get('resolution')))

    def test_ext01_method_helper_removal_loses_unit_coverage(self):
        """EXT-METHOD-01 baseline control: an external test whose helper
        is a concrete method on a group type calls production Allowed
        while the same test also calls production Guarded directly.
        Removing ONLY the method invocation — the helper method itself
        stays byte-identical and the direct Guarded call keeps the test
        green — must still lose Allowed from real baseline coverage and
        block with a named lost_unit_coverage error. Independent leg
        proofs run the real suite on this fixture before each phase."""
        module = self.write_module('fnbothm', {
            'pkg/auth/auth.go': ('package auth\n\n'
                                 'func Allowed(n int) bool { return n > 0 }\n\n'
                                 'func Guarded(n int) bool { return n > 1 }\n'),
            'pkg/auth/method_helper_test.go': (
                'package auth_test\n\nimport (\n'
                '\t"example.test/fnbothm/pkg/auth"\n)\n\n'
                'type probe struct{}\n\n'
                'func (p probe) allow() bool {\n'
                '\treturn auth.Allowed(6)\n}\n'),
            'pkg/auth/method_caller_test.go': (
                'package auth_test\n\nimport (\n\t"testing"\n\n'
                '\t"example.test/fnbothm/pkg/auth"\n)\n\n'
                'func TestMethodBothPaths(t *testing.T) {\n'
                '\tif fn := (probe{}).allow; !fn() {\n'
                '\t\tt.Fatal("method helper must execute")\n'
                '\t}\n'
                '\tif !auth.Guarded(2) {\n'
                '\t\tt.Fatal("direct production call must execute")\n'
                '\t}\n}\n'),
        })
        for argv in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=module, text=True).strip()
        run = subprocess.run(['go', 'test', './...'], cwd=module,
                             capture_output=True, text=True,
                             env=self.go_env(), timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        # Test-only edit for phase A: the helper method stays
        # byte-identical; only the calling test's fingerprint changes.
        testfile = module / 'pkg/auth/method_caller_test.go'
        testfile.write_text(testfile.read_text().replace(
            't.Fatal("direct production call must execute")',
            't.Fatal("direct production call must still execute")'))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'test-only fingerprint edit']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV, critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            selected = critical_scope.targets(
                module, base, {'critical_paths': ['pkg/auth/**']})
            evidence = critical_scope.selection_evidence()['pkg/auth']['reasons']
        except ValueError as exc:
            self.fail(f'phase A lost coverage unexpectedly: {exc}')
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        names = {fn['name'] for fn in selected.get('pkg/auth', [])}
        self.assertEqual(
            names, {'Allowed', 'Guarded'},
            f"conservative final selection 'Allowed' not found beside "
            f"'Guarded' in {sorted(names)}")
        self.assertNotIn('*', evidence, evidence)
        # Rewrite: drop ONLY the method invocation; the helper method
        # itself stays byte-identical and the direct Guarded call keeps
        # the test green.
        testfile.write_text(testfile.read_text().replace(
            '\tif fn := (probe{}).allow; !fn() {\n'
            '\t\tt.Fatal("method helper must execute")\n'
            '\t}\n', ''))
        for argv in (['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'drop method invocation only']):
            subprocess.run(['git', *argv], cwd=module, check=True,
                           capture_output=True)
        run = subprocess.run(['go', 'test', './...'], cwd=module,
                             capture_output=True, text=True,
                             env=self.go_env(), timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        saved = {}
        for key, value in (('GOWORK', 'off'), ('GOFLAGS', ''),
                           ('GOTOOLCHAIN', 'go1.27.4'),
                           (critical_scope.MODE_ENV, critical_scope.CONSERVATIVE)):
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            with self.assertRaises(ValueError) as caught:
                critical_scope.targets(
                    module, base, {'critical_paths': ['pkg/auth/**']})
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertIn('lost_unit_coverage', str(caught.exception),
                      caught.exception)
        self.assertIn('Allowed', str(caught.exception), caught.exception)

    def test_load01_assembler_error_fails_closed_both_paths(self):
        """LOAD-ERR-01: a real package-load error — an assembler error
        in broken.s that type checking never sees, with a working
        standard-library dependency — fails the mode closed through the
        exports listing, and goListPackageInfo itself fails closed under
        -export through a direct test-only invocation of the real
        function. The committed original silently certified the broken
        package, and a marker-disabled splice proves the marker checks
        are the operative gates."""
        module = self.write_module('fnloaderr', {
            'auth.go': ('package fnloaderr\n\nimport "fmt"\n\n'
                        'func Allowed(n int) string {\n'
                        '\treturn fmt.Sprintf("ok-%d", n)\n'
                        '}\n'),
            'broken.s': 'TEXT ·broken(SB),$0\nINVALID\n',
        })

        def probe_package_info(src, tag):
            """Invoke the REAL goListPackageInfo on the same module via
            a test-only main() dispatch seam spliced into a copy; the
            function body itself is untouched production source."""
            anchor = 'func main() {\n\tif err := run(); err != nil {'
            dispatch = ('func main() {\n'
                        '\tif len(os.Args) > 2 && '
                        'os.Args[1] == "--probe-package-info" {\n'
                        '\t\tctx, cancel := context.WithTimeout('
                        'context.Background(), analysisBudget)\n'
                        '\t\tdefer cancel()\n'
                        '\t\tip, name, err := goListPackageInfo('
                        'os.Args[2], nil, ctx)\n'
                        '\t\tif err != nil {\n'
                        '\t\t\tfmt.Fprintln(os.Stderr, err)\n'
                        '\t\t\tos.Exit(3)\n'
                        '\t\t}\n'
                        '\t\tfmt.Printf("%s %s\\n", ip, name)\n'
                        '\t\treturn\n'
                        '\t}\n'
                        '\tif err := run(); err != nil {')
            self.assertEqual(src.count(anchor), 1, 'seam anchor missing')
            path = self.root / f'probe_{tag}.go'
            path.write_text(src.replace(anchor, dispatch, 1))
            return subprocess.run(
                ['go', 'run', str(path), '--probe-package-info',
                 str(module)], cwd=module, capture_output=True,
                text=True, env=self.go_env(), timeout=110)

        # Frozen original (committed 76528f8): clean resolution and a
        # succeeding package-info lookup — the defect this item pins.
        original = frozen_blob('budget_units')
        self.assertEqual(
            self.run_units(module, ['auth.go'], [[]],
                           helper=self.write_helper(original,
                                                    'load01_orig'),
                           )['auth.go'].get('resolution', []),
            [], 'frozen original must stay silently clean (defect pinned)')
        self.assertEqual(
            probe_package_info(original, 'load01_orig').stdout.strip(),
            'example.test/fnloaderr fnloaderr',
            'frozen original package-info lookup must succeed')

        # Fixed: the mode floors through the real exports listing with
        # the actual failing import path in the note.
        rows = self.run_units(module, ['auth.go'], [[]])
        notes = rows['auth.go'].get('resolution') or []
        self.assertTrue(
            any('mode go list failed' in n
                and 'package load error: example.test/fnloaderr' in n
                for n in notes), notes)
        # Fixed: the real goListPackageInfo fails closed under -export
        # on the same module.
        probe = probe_package_info(self.helper.read_text(),
                                   'load01_fixed')
        # `go run` maps the program's os.Exit(3) to outer rc=1 and
        # reports the program's own exit status on stderr.
        self.assertEqual(probe.returncode, 1, probe.stdout + probe.stderr)
        self.assertIn('go list package info: package load error: '
                      'example.test/fnloaderr', probe.stderr)
        self.assertIn('exit status 3', probe.stderr)

        # Isolated: disable ONLY the two marker checks; both paths
        # silently accept the broken package again, so the checks are
        # the operative gates.
        current = self.helper.read_text()
        self.assertEqual(current.count('if parts[2] == "1" {'), 2,
                         'expected exactly two marker checks')
        isolated = current.replace('if parts[2] == "1" {',
                                   'if parts[2] == "9" {')
        self.assertEqual(
            self.run_units(module, ['auth.go'], [[]],
                           helper=self.write_helper(isolated,
                                                    'load01_iso'),
                           )['auth.go'].get('resolution', []),
            [], 'marker-disabled splice must silently accept the module')
        probe = probe_package_info(isolated, 'load01_iso')
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        self.assertEqual(probe.stdout.strip(),
                         'example.test/fnloaderr fnloaderr')

    def write_helper(self, src, tag):
        path = self.root / f'units_{tag}.go'
        path.write_text(src)
        return path

    def test_pgid01_lifecycle_guards(self):
        """PGID-01: the exclusive-reaper lifecycle signals the owned
        process group exactly once, before the single Wait, serialized
        against Cancel. Isolated no-real-signal recorders classify each
        observation site: the committed original signaled only after
        Wait (B), the fixed lifecycle signals while the child identity
        is reserved (A), a moved-after-Wait signal block regresses to
        B, a deleted block emits nothing, and a paused Cancel proves
        serialization — the reap cannot pass it, the release performs
        the control's only real cleanup kill, and a second Cancel
        reports os.ErrProcessDone. Every launched session is guarded
        and drained; the barrier holds a real live inner child through
        a delaying wrapper, never wall-clock luck."""
        module = self.write_module('fnpgid01', {
            'shared.go': ('package fnpgid01\n\n'
                          'func Allowed(n int) bool { return n > 0 }\n'),
        })
        real_go = shutil.which('go')
        self.assertIsNotNone(real_go)
        source = self.helper.read_text()
        original = frozen_blob('budget_units')

        cancel_ret = ('\t\treturn syscall.Kill(-cmd.Process.Pid, '
                      'syscall.SIGKILL)\n')
        final_sig = ('\t\tsigErr = syscall.Kill(-cmd.Process.Pid, '
                     'syscall.SIGKILL)\n')
        signal_block = ('\tmu.Lock()\n'
                        '\tif armed {\n'
                        '\t\tsigErr = syscall.Kill(-cmd.Process.Pid, '
                        'syscall.SIGKILL)\n'
                        '\t\tarmed = false\n'
                        '\t}\n'
                        '\tmu.Unlock()\n')
        # The moved mutant relocates only these signal statements; the
        # sigErr declaration stays in place so the variant compiles and
        # remains a behavioral negative.
        probed_block = signal_block.replace(
            'sigErr = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)',
            'sigErr = probeRecordSignal(cmd.Process.Pid)')
        waitline = '\n\twerr := cmd.Wait()\n'
        func_anchor = 'func runGoList('
        main_anchor = 'func main() {\n\tif err := run(); err != nil {'
        orig_cleanup = ('\t\t_ = syscall.Kill(-cmd.Process.Pid, '
                        'syscall.SIGKILL)\n')
        startline = '\tif err := cmd.Start(); err != nil {\n'
        wait_ret = ('\tif err := waitExited(cmd.Process.Pid); '
                    'err != nil {\n')
        cancel_open = '\tcmd.Cancel = func() error {\n'
        fail_wait = '\t\twerr := cmd.Wait()\n'
        sig_decl = '\tvar sigErr error\n'

        trace_head = (
            '// test-only barrier diagnostics: inert unless '
            'PGID_TRACE_LOG\n'
            '// is set; elapsed is monotonic since helper start.\n'
            'var probeT0 time.Time\n'
            '\n'
            'func probeTrace(msg string) {\n'
            '\tif p := os.Getenv("PGID_TRACE_LOG"); p != "" {\n'
            '\t\tif f, ferr := os.OpenFile(p,\n'
            '\t\t\tos.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); ferr == nil {\n'
            '\t\t\tfmt.Fprintf(f, "%s %s\\n",\n'
            '\t\t\t\ttime.Since(probeT0).Round(time.Millisecond), msg)\n'
            '\t\t\t_ = f.Close()\n'
            '\t\t}\n'
            '\t}\n'
            '}\n'
            '\n')
        recorder = (
            trace_head +
            '// probeRecordSignal is a test-only recorder: it classifies\n'
            '// which lifecycle site observed the child — A already exited\n'
            '// and still waitable, B already reaped elsewhere, R still\n'
            '// running — through waitid(WNOHANG) and never delivers a\n'
            '// real signal. PAUSE holds the callback until the test\n'
            '// writes the release file. Measured waitid siginfo layout:\n'
            '// si_pid occupies bytes 16-19 — uint32(info[2]) — si_uid\n'
            '// bytes 20-23, and bytes 12-15 stay zero even for an\n'
            '// exited child. Generation A therefore requires the\n'
            '// exited original child\'s own PID, still waitable.\n'
            'func probeRecordSignal(pid int) error {\n'
            '\tvar info [16]uint64\n'
            '\t_, _, errno := syscall.Syscall6(syscall.SYS_WAITID,\n'
            '\t\tuintptr(1) /* P_PID */, uintptr(pid),\n'
            '\t\tuintptr(unsafe.Pointer(&info[0])),\n'
            '\t\tuintptr(syscall.WEXITED|syscall.WNOWAIT|syscall.WNOHANG), 0, 0)\n'
            '\tif errno == syscall.ECHILD {\n'
            '\t\tprobeLog("B", pid)\n'
            '\t\treturn nil\n'
            '\t}\n'
            '\tif errno != 0 {\n'
            '\t\treturn fmt.Errorf("probe waitid: %v", errno)\n'
            '\t}\n'
            '\tif uint32(info[2]) == uint32(pid) {\n'
            '\t\tprobeLog("A", pid)\n'
            '\t} else {\n'
            '\t\tprobeLog("R", pid)\n'
            '\t}\n'
            '\tfor os.Getenv("PGID_PROBE_PAUSE") == "1" {\n'
            '\t\tif _, serr := os.Stat(os.Getenv("PGID_PROBE_RELEASE")); serr == nil {\n'
            '\t\t\tbreak\n'
            '\t\t}\n'
            '\t\ttime.Sleep(10 * time.Millisecond)\n'
            '\t}\n'
            '\treturn nil\n'
            '}\n'
            '\n'
            'func probeLog(gen string, pid int) {\n'
            '\tif f, ferr := os.OpenFile(os.Getenv("PGID_PROBE_LOG"),\n'
            '\t\tos.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); ferr == nil {\n'
            '\t\tfmt.Fprintf(f, "%s %d\\n", gen, pid)\n'
            '\t\t_ = f.Close()\n'
            '\t}\n'
            '}\n'
            '\n')
        barrier_recorder_head = (
            '// probeBarrierKill is the barrier-only recorder: the same\n'
            '// no-signal classification and pause as probeRecordSignal,\n'
            '// then the single real cleanup kill of the owned process\n'
            '// group — the only real signal this control ever emits.\n'
            'func probeBarrierKill(pid int) error {\n'
            '\tvar info [16]uint64\n'
            '\t_, _, errno := syscall.Syscall6(syscall.SYS_WAITID,\n'
            '\t\tuintptr(1) /* P_PID */, uintptr(pid),\n'
            '\t\tuintptr(unsafe.Pointer(&info[0])),\n'
            '\t\tuintptr(syscall.WEXITED|syscall.WNOWAIT|syscall.WNOHANG), 0, 0)\n'
            '\tif errno == syscall.ECHILD {\n'
            '\t\tprobeLog("B", pid)\n'
            '\t\treturn nil\n'
            '\t}\n'
            '\tif errno != 0 {\n'
            '\t\treturn fmt.Errorf("probe waitid: %v", errno)\n'
            '\t}\n'
            '\tif uint32(info[2]) == uint32(pid) {\n'
            '\t\tprobeLog("A", pid)\n'
            '\t} else {\n'
            '\t\tprobeLog("R", pid)\n'
            '\t}\n'
            '\tfor os.Getenv("PGID_PROBE_PAUSE") == "1" {\n'
            '\t\tif _, serr := os.Stat(os.Getenv("PGID_PROBE_RELEASE")); serr == nil {\n'
            '\t\t\tbreak\n'
            '\t\t}\n'
            '\t\ttime.Sleep(10 * time.Millisecond)\n'
            '\t}\n'
            '\treturn syscall.Kill(-pid, syscall.SIGKILL)\n'
            '}\n'
            '\n')
        dispatch = ('func main() {\n'
                    '\tprobeT0 = time.Now()\n'
                    '\tif len(os.Args) > 2 && '
                    'os.Args[1] == "--probe-signals" {\n'
                    '\t\tip, pkg, perr := goListPackageInfo('
                    'os.Args[2], nil, context.Background())\n'
                    '\t\tif perr != nil {\n'
                    '\t\t\tfmt.Fprintln(os.Stderr, perr)\n'
                    '\t\t\tos.Exit(3)\n'
                    '\t\t}\n'
                    '\t\tfmt.Printf("%s %s\\n", ip, pkg)\n'
                    '\t\treturn\n'
                    '\t}\n'
                    '\tif len(os.Args) > 3 && '
                    'os.Args[1] == "--probe-cancel-barrier" {\n'
                    '\t\tbctx, bcancel := context.WithTimeout('
                    'context.Background(), 150*time.Millisecond)\n'
                    '\t\tdefer bcancel()\n'
                    '\t\tbpath, blperr := exec.LookPath("go")\n'
                    '\t\tprobeTrace(fmt.Sprintf('
                    '"barrier-branch path-env=%q lookpath=%q lperr=%v", '
                    'os.Getenv("PATH"), bpath, blperr))\n'
                    '\t\t_, berr := runGoList(bctx, os.Args[2], "list", '
                    '"-e", os.Args[3])\n'
                    '\t\tprobeTrace(fmt.Sprintf('
                    '"barrier runGoList err=%v", berr))\n'
                    '\t\tif berr != nil {\n'
                    '\t\t\tfmt.Fprintln(os.Stderr, berr)\n'
                    '\t\t\tos.Exit(2)\n'
                    '\t\t}\n'
                    '\t\tfmt.Println("probe-ok")\n'
                    '\t\treturn\n'
                    '\t}\n'
                    '\tif err := run(); err != nil {')

        def run_ab(tag, base, splices, expected):
            """Build an isolated copy, invoke the REAL goListPackageInfo
            through the dispatch seam and require the exact observation
            sequence; rc must stay 0, so a compile error or an aborted
            listing is never a pass."""
            src = self.deadline_copy(f'units-pgid-{tag}.go', source=base,
                                     splices=splices)
            log = self.root / f'pgid-{tag}.probe.log'
            if log.exists():
                log.unlink()
            run = self.guarded_helper(
                ['go', 'run', str(src), '--probe-signals', str(module)],
                module, self.go_env(PGID_PROBE_LOG=str(log)), '',
                timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual(run.stdout.strip(),
                             'example.test/fnpgid01 fnpgid01')
            lines = log.read_text().splitlines() if log.exists() else []
            self.assertEqual([line.split(None, 1)[0] for line in lines],
                             expected, f'{tag}: {lines}')
            return lines

        # Original (committed 76528f8): the only group signal runs after
        # Wait already reaped the leader — B — so its cleanup can never
        # cover a descendant that outlives the leader.
        run_ab('original', original, [
            ('\t"syscall"\n', '\t"syscall"\n\t"unsafe"\n'),
            (func_anchor, recorder + func_anchor),
            (cancel_ret,
             '\t\treturn probeRecordSignal(cmd.Process.Pid)\n'),
            (orig_cleanup,
             '\t\t_ = probeRecordSignal(cmd.Process.Pid)\n'),
            (main_anchor, dispatch),
        ], ['B'])

        # Fixed: exactly one group signal, observed while the exited
        # child is still waitable — A — before the single Wait.
        run_ab('fixed', source, [
            (func_anchor, recorder + func_anchor),
            (cancel_ret,
             '\t\treturn probeRecordSignal(cmd.Process.Pid)\n'),
            (final_sig,
             '\t\tsigErr = probeRecordSignal(cmd.Process.Pid)\n'),
            (main_anchor, dispatch),
        ], ['A'])

        # Moved-after-Wait mutant: the declaration stays, only the
        # signal statements relocate past the reap — B, the original
        # defect, not a compile failure.
        run_ab('moved', source, [
            (func_anchor, recorder + func_anchor),
            (cancel_ret,
             '\t\treturn probeRecordSignal(cmd.Process.Pid)\n'),
            (waitline, waitline + probed_block),
            (signal_block, ''),
            (main_anchor, dispatch),
        ], ['B'])

        # Deleted-block mutant: declaration kept, no site signals —
        # zero observations while the listing still succeeds.
        run_ab('deleted', source, [
            (func_anchor, recorder + func_anchor),
            (cancel_ret,
             '\t\treturn probeRecordSignal(cmd.Process.Pid)\n'),
            (signal_block, ''),
            (main_anchor, dispatch),
        ], [])

        # Paused-Cancel barrier: a wrapper around the real go delays the
        # inner listing, so the child is provably alive when the 150ms
        # context fires; the recorder classifies R and holds the Cancel
        # callback under the production mutex. Nothing may reap past it;
        # the release performs the control's only real cleanup kill, the
        # deadline path surfaces as the directly executed helper's own
        # rc=2, and a second Cancel must report os.ErrProcessDone. The
        # whole session is registered and drained on any outcome.
        wrapper = self.root / 'pgidwrap'
        wrapper.mkdir()
        wrapper_go = wrapper / 'go'
        wrapper_go.write_text(
            '#!/bin/sh\n'
            '# test-only: guarantee a live inner child at cancellation and\n'
            '# record wrapper entry (pre-sleep) and exec (post-sleep) so a\n'
            '# bypass is provable from the sidecar timestamps\n'
            '[ -n "$PGID_WRAP_TRACE" ] && '
            'echo "enter $(date +%s%N) pid=$$ argv=$*" '
            '>> "$PGID_WRAP_TRACE"\n'
            'sleep 1\n'
            '[ -n "$PGID_WRAP_TRACE" ] && '
            'echo "preexec $(date +%s%N) pid=$$" >> "$PGID_WRAP_TRACE"\n'
            f'exec {real_go} "$@"\n')
        wrapper_go.chmod(0o755)
        btrace = self.root / 'pgid-barrier.trace'
        wtrace = self.root / 'pgid-wrapper.trace'
        for stale in (btrace, wtrace):
            if stale.exists():
                stale.unlink()

        def evidence():
            """Everything needed to diagnose a barrier failure in one
            message: probe generations, lifecycle trace and the wrapper
            sidecar."""
            parts = []
            for label, path in (('blog', blog), ('trace', btrace),
                                ('wrap', wtrace)):
                content = (path.read_text().splitlines()
                           if path.exists() else [])
                parts.append(f'{label}={content}')
            return ' '.join(parts)
        blog = self.root / 'pgid-barrier.probe.log'
        if blog.exists():
            blog.unlink()
        release = self.root / 'pgid-barrier.release'
        second = (
            '\t// test-only: a Cancel after the single Wait must report\n'
            '\t// completion, never signal a possibly reused process group;\n'
            '\t// logged unconditionally so a wrong result fails the exact\n'
            '\t// expected line below\n'
            '\tprobeLog(fmt.Sprintf("second %v", cmd.Cancel()), 0)\n')
        barrier_src = self.deadline_copy(
            'units-pgid-barrier.go', source=source, splices=[
                (func_anchor,
                 recorder + barrier_recorder_head + func_anchor),
                (startline,
                 '\tprobeTrace(fmt.Sprintf('
                 '"pre-start path=%q", cmd.Path))\n'
                 + startline),
                (wait_ret,
                 '\tprobeTrace(fmt.Sprintf('
                 '"post-start direct pid=%d path=%q", '
                 'cmd.Process.Pid, cmd.Path))\n'
                 + wait_ret),
                (cancel_open,
                 cancel_open + '\t\tprobeTrace("cancel-entry pre-mu")\n'),
                (cancel_ret,
                 '\t\tprobeTrace("cancel classify-entry")\n'
                 '\t\tbkErr := probeBarrierKill(cmd.Process.Pid)\n'
                 '\t\tprobeTrace(fmt.Sprintf('
                 '"cancel classify-exit err=%v", bkErr))\n'
                 '\t\treturn bkErr\n'),
                (fail_wait,
                 '\t\tprobeTrace("waitExited-error branch")\n' + fail_wait),
                (sig_decl,
                 '\tprobeTrace('
                 '"waitExited-returned+final-prelock")\n'
                 + sig_decl),
                (final_sig,
                 '\t\tprobeTrace("final classify-entry")\n'
                 '\t\tsigErr = probeRecordSignal(cmd.Process.Pid)\n'
                 '\t\tprobeTrace(fmt.Sprintf('
                 '"final classify-exit sigErr=%v", sigErr))\n'),
                (waitline, waitline + second),
                (main_anchor, dispatch),
            ])
        benv = self.go_env(
            PATH=f'{wrapper}{os.pathsep}{os.environ["PATH"]}',
            PGID_PROBE_LOG=str(blog), PGID_PROBE_PAUSE='1',
            PGID_PROBE_RELEASE=str(release),
            PGID_TRACE_LOG=str(btrace), PGID_WRAP_TRACE=str(wtrace))
        # Direct-launch PATH invariant: an outer `go run` rewrites the
        # child PATH to put the toolchain bin first, which would
        # silently bypass the delaying wrapper. The helper is therefore
        # built with the absolute real toolchain and executed directly;
        # only the nested listing resolves `go` through the
        # wrapper-first PATH, and the wrapper execs the pinned absolute
        # toolchain, keeping the listing deterministic.
        helper_bin = self.root / 'pgid-barrier-helper'
        build = self.guarded_helper(
            [real_go, 'build', '-o', str(helper_bin), str(barrier_src)],
            module, self.go_env(), '', timeout=300)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        proc = subprocess.Popen(
            [str(helper_bin), '--probe-cancel-barrier',
             str(module), 'example.test/fnpgid01'],
            cwd=str(module), text=True, env=benv,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        self._guard_sids.append(proc.pid)
        try:
            # Phase one: R from the paused Cancel AND the final block
            # parked before the held mutex. The delayed wrapper child
            # finishes naturally while Cancel is paused, so reaching
            # final-prelock proves reaping waits behind the mutex —
            # outer liveness alone would not.
            phase1 = time.monotonic() + 60
            while True:
                blines = (blog.read_text().splitlines()
                          if blog.exists() else [])
                tlines = (btrace.read_text().splitlines()
                          if btrace.exists() else [])
                r_seen = any(ln.startswith('R ') for ln in blines)
                parked = any(
                    'waitExited-returned+final-prelock' in ln
                    for ln in tlines)
                if r_seen and parked:
                    break
                if proc.poll() is not None:
                    out, err = proc.communicate()
                    self.fail('helper exited before paused Cancel and '
                              f'blocked final were observed: '
                              f'rc={proc.returncode} '
                              f'stderr={err[-400:]} {evidence()}')
                self.assertLess(time.monotonic(), phase1,
                                'barrier never reached paused Cancel '
                                'plus mutex-blocked final within 60s: '
                                + evidence())
                time.sleep(0.05)
            # While Cancel is paused and final is blocked on the mutex:
            # no classification exit, no final classify, nothing reaped,
            # no release yet, helper alive.
            tlines = btrace.read_text().splitlines()
            self.assertFalse(
                any('cancel classify-exit' in ln for ln in tlines),
                'Cancel left its paused region before release: '
                + evidence())
            self.assertFalse(
                any('final classify-entry' in ln for ln in tlines),
                'final ran while Cancel held the mutex: ' + evidence())
            self.assertFalse(release.exists())
            self.assertIsNone(
                proc.poll(),
                'helper finished while Cancel was paused and final '
                'blocked: ' + evidence())
            # The wrapper really served the nested listing — entry before
            # its sleep, exec after it — and the direct child IS the
            # wrapper process, not a bypassed toolchain binary.
            wlines = (wtrace.read_text().splitlines()
                      if wtrace.exists() else [])
            enters = [ln for ln in wlines if ln.startswith('enter ')]
            preexecs = [ln for ln in wlines if ln.startswith('preexec ')]
            self.assertTrue(enters and preexecs,
                            'wrapper never served the nested listing '
                            '(bypass): ' + evidence())
            self.assertIn('argv=list -e example.test/fnpgid01',
                          enters[0], evidence())
            wrap_pid = int(enters[0].split('pid=')[1].split()[0])
            posts = [ln for ln in tlines
                     if 'post-start direct pid=' in ln]
            self.assertTrue(posts, evidence())
            self.assertIn(f'direct pid={wrap_pid} ', posts[0],
                          'direct child is not the wrapper process: '
                          + evidence())
            self.assertTrue(
                any('cancel-entry pre-mu' in ln for ln in tlines),
                evidence())
            self.assertTrue(
                any('cancel classify-entry' in ln for ln in tlines),
                evidence())
            release.write_text('')
            out, err = proc.communicate(timeout=90)
            self.assertEqual(proc.returncode, 2, out + err)
            self.assertIn('deadline exceeded', err)
            lines = blog.read_text().splitlines() if blog.exists() else []
            self.assertEqual(
                [line.split(None, 1)[0] for line in lines],
                ['R', 'A', 'second'], lines)
            self.assertIn('os: process already finished', lines[2])
            # The lifecycle trace proves the serialization order: cancel
            # entry and classification first, final parked at the mutex
            # while Cancel was paused, classification exit only after the
            # release, final classification after that.
            tlines = btrace.read_text().splitlines()
            order = ['cancel-entry pre-mu', 'cancel classify-entry',
                     'waitExited-returned+final-prelock',
                     'cancel classify-exit', 'final classify-entry',
                     'final classify-exit']
            pos = []
            for marker in order:
                hits = [i for i, ln in enumerate(tlines) if marker in ln]
                self.assertTrue(hits,
                                f'missing trace marker {marker}: '
                                f'{tlines}')
                pos.append(hits[0])
            self.assertEqual(pos, sorted(pos),
                             'lifecycle trace out of order: ' + evidence())
            time.sleep(1)
            self.assertEqual(self.session_members(proc.pid), [],
                             'barrier session leaked descendants')
        except BaseException:
            self.drain_session(proc.pid)
            raise
        finally:
            # Successful evidence must survive fixture cleanup when the
            # runner supplies a per-run directory.
            ev_dir = os.environ.get('R2_PGID_EVIDENCE_DIR')
            if ev_dir:
                ev = Path(ev_dir)
                ev.mkdir(parents=True, exist_ok=True)
                for artifact in (blog, btrace, wtrace):
                    if artifact.exists():
                        (ev / artifact.name).write_bytes(
                            artifact.read_bytes())

    def test_mode01_tagged_twins_group_per_mode(self):
        """MODE-01: package metadata follows the mode's tags. Tagged
        package-clause twins with different names, their external test
        twins and a tag-only package group correctly in every mode and
        bind without fallback; the request keeps the exact production
        shape (default mode [], real tag sets otherwise)."""
        module = self.write_module('fnmodes', {
            'base.go': ('//go:build !exp && !special\n\npackage alpha\n\n'
                        'func Target() bool { return true }\n'),
            'twin.go': ('//go:build exp && !special\n\npackage beta\n\n'
                        'func Target() bool { return true }\n'),
            'ext_alpha_test.go': ('//go:build !exp && !special\n\npackage alpha_test\n\nimport (\n'
                                  '\t"testing"\n\n'
                                  '\t"example.test/fnmodes"\n)\n\n'
                                  'func TestAlphaExt(t *testing.T) {\n'
                                  '\tif !alpha.Target() { t.Fatal("alpha target must run") }\n}\n'),
            'ext_beta_test.go': ('//go:build exp && !special\n\npackage beta_test\n\nimport (\n'
                                 '\t"testing"\n\n'
                                 '\t"example.test/fnmodes"\n)\n\n'
                                 'func TestBetaExt(t *testing.T) {\n'
                                 '\tif !beta.Target() { t.Fatal("beta target must run") }\n}\n'),
            'only.go': ('//go:build special\n\npackage gamma\n\n'
                        'func GammaOnly() bool { return true }\n'),
        })
        rows = self.run_units(module, ['base.go', 'twin.go', 'ext_alpha_test.go',
                                       'ext_beta_test.go', 'only.go'],
                              [[], ['exp'], ['special']])
        for path, out in rows.items():
            self.assertEqual(out.get('resolution') or [], [], (path, out.get('resolution')))
        self.assertEqual(rows['base.go']['matched'], [True, False, False])
        self.assertEqual(rows['twin.go']['matched'], [False, True, False])
        self.assertEqual(rows['ext_alpha_test.go']['matched'], [True, False, False])
        self.assertEqual(rows['ext_beta_test.go']['matched'], [False, True, False])
        self.assertEqual(rows['only.go']['matched'], [False, False, True])
        self.assertIn('Target', self.unit(rows['ext_alpha_test.go'], 'TestAlphaExt').get('refs') or [])
        self.assertIn('Target', self.unit(rows['ext_beta_test.go'], 'TestBetaExt').get('refs') or [])

    def test_time01_deadline_floors_every_mode(self):
        """TIME-01: a deadline expired during one mode floors the whole
        analysis through an isolated short-budget copy of the helper (the
        production budget is untouched). Declarations the first mode had
        resolved narrowly regain the name-based floor — including the
        shadowed reference the type check proved local — so the dynamic
        widening the unexamined third mode owed survives; termination is
        bounded with no partial certification and no abandoned helper
        descendants."""
        module = self.root / 'fntime'
        module.mkdir(parents=True)
        (module / 'go.mod').write_text('module example.test/fntime\n\ngo 1.27\n')
        (module / 'shared.go').write_text(
            '//go:build !m2\n\npackage fntime\n\n'
            'type runner interface{ Dispatch() bool }\n\n'
            'func Always(r runner) bool { return r.Dispatch() }\n\n'
            'func Shadowed() bool { Dispatch := true; return Dispatch }\n\n'
            'func Dispatch(n int) bool { return n > 0 }\n')
        (module / 'm1only.go').write_text(
            '//go:build m1\n\npackage fntime\n\nfunc First() bool { return Dispatch(1) }\n')
        (module / 'm3only.go').write_text(
            '//go:build m3\n\npackage fntime\n\nfunc Third() bool { return Dispatch(3) }\n')
        big = ['//go:build m2', '', f'// nonce {os.urandom(8).hex()}',
               'package fntime', '']
        big += [f'func F{i}() int {{ return {i} }}' for i in range(80000)]
        (module / 'big.go').write_text('\n'.join(big) + '\n')
        source = self.helper.read_text()
        self.assertEqual(source.count('90 * time.Second'), 1)
        env = dict(os.environ, GOWORK='off', GOFLAGS='', GOTOOLCHAIN='go1.27.4')
        for tags in ('', 'm1', 'm2', 'm3'):
            argv = ['go', 'list', '-deps', '-export', '-test']
            if tags:
                argv += ['-tags', tags]
            subprocess.run(argv + ['.'], cwd=module, capture_output=True,
                           env=env, timeout=100, check=True)
        request = json.dumps({'paths': ['shared.go', 'm1only.go', 'm3only.go', 'big.go'],
                              'modes': [['m1'], ['m2'], ['m3']]})

        # HARNESS-GUARD-01: every launch in this control goes through the
        # guarded launcher — the original direct Popen launcher had no
        # containment and must never run again.

        # Barrier copy: the isolated helper expires the shared context
        # deterministically between modes. The first mode resolves
        # narrowly, then the production loop-top deadline gate floors
        # every file through the production markFloor path. No wall
        # clock is involved and the production request, algorithm and
        # 90s budget are untouched; the state transition is controlled,
        # and the same run proves it: every row carries the deadline
        # note while Shadowed regains the name-based Dispatch floor the
        # narrow first mode had excluded.
        barrier = self.root / 'units-r2barrier.go'
        sig = ('func analyze(files []parsedFile, paths []string, '
               'modes [][]string, ctx context.Context) *resolution {')
        sig_barrier = (sig + '\n\t// test-only barrier: controllable expiry between modes\n'
                       '\tctx, barrierCancel := context.WithCancel(ctx)\n'
                       '\tdefer barrierCancel()')
        gate = '\tfor _, mode := range modeList {\n\t\tif ctx.Err() != nil {'
        gate_barrier = ('\tfor modeIndex, mode := range modeList {\n'
                        '\t\tif modeIndex == 1 {\n'
                        '\t\t\t// test-only barrier: expire after the first narrow mode\n'
                        '\t\t\tbarrierCancel()\n'
                        '\t\t}\n'
                        '\t\tif ctx.Err() != nil {')
        self.assertEqual(source.count(sig), 1)
        self.assertEqual(source.count(gate), 1)
        barrier.write_text(source.replace(sig, sig_barrier).replace(gate, gate_barrier))
        _, rows = self.guarded_go_run(module, env, barrier, request)
        for path, out_row in rows.items():
            self.assertTrue(any('analysis deadline exceeded' in note
                                for note in out_row.get('resolution') or []),
                            (path, out_row.get('resolution')))
        shadowed = self.unit(rows['shared.go'], 'Shadowed')
        self.assertIn('Dispatch', shadowed.get('refs') or [],
                     (shadowed, rows['shared.go'].get('resolution')))
        always = self.unit(rows['shared.go'], 'Always')
        self.assertIn('Dispatch', always.get('selrefs') or [], always)

        # Kill copy: a real go list subprocess is alive when its context
        # expires, so the production group-kill machinery — SIGKILL on
        # the child process group, bounded wait — must reap the tree.
        # The note text is the liveness proof: a listing that finished
        # before the expiry cannot report its own kill. The m2 listing
        # over the nonce-annotated 80k-function fixture forces a real
        # recompile of a second or more, so the 50ms trigger fires
        # provably mid-child. Cancellation
        # between modes above is never treated as proof of killing a
        # live child; this case alone anchors the descendant oracle.
        kill = self.root / 'units-r2kill.go'
        spawn = '\tcmd := exec.CommandContext(ctx, "go", args...)'
        spawn_kill = ('\tkillCtx, killCancel := context.WithCancel(ctx)\n'
                      '\tdefer killCancel()\n'
                      '\tcmd := exec.CommandContext(killCtx, "go", args...)')
        startline = '\tif err := cmd.Start(); err != nil {'
        startline_kill = ('\tgo func() {\n'
                          '\t\ttime.Sleep(50 * time.Millisecond)\n'
                          '\t\tkillCancel()\n'
                          '\t}()\n'
                          '\tif err := cmd.Start(); err != nil {')
        self.assertEqual(source.count(spawn), 1)
        self.assertEqual(source.count(startline), 1)
        kill.write_text(source.replace(spawn, spawn_kill)
                        .replace(startline, startline_kill))
        # Fresh nonce: the primed m2 listing would be a cache hit and
        # could finish inside the trigger window; a fresh compile runs
        # for seconds, so the expiry provably lands mid-child.
        big[2] = f'// nonce {os.urandom(8).hex()}'
        (module / 'big.go').write_text('\n'.join(big) + '\n')
        kill_req = json.dumps({'paths': ['shared.go', 'big.go'], 'modes': [['m2']]})
        sid, rows = self.guarded_go_run(module, env, kill, kill_req)
        self.assertTrue(any('signal: killed' in note
                            for note in rows['big.go'].get('resolution') or []),
                        rows['big.go'].get('resolution'))
        self.assertIn('resolution-fallback: no mode type-checked',
                      rows['shared.go'].get('resolution') or [])
        # Process oracle: the kill-copy helper ran as its own guard
        # session leader, so every descendant — go run, the compiled
        # helper, its killed go list subprocess and any compiler workers
        # it had spawned — shares that session id unless abandoned. The
        # sid is the launcher's real session (self.last_sid), this check
        # runs after the product's own cleanup and before teardown's
        # drain, and scanning /proc for session members is exact: no
        # text match on command lines, no unrelated processes.
        time.sleep(2)
        members = self.session_members(sid)
        self.assertEqual(members, [], f'abandoned session descendants: {members}')

    # --- deadline-during-check controls ---------------------------------

    def go_env(self, **extra):
        env = dict(os.environ, GOWORK='off', GOFLAGS='', GOTOOLCHAIN='go1.27.4')
        env.update(extra)
        return env

    @staticmethod
    def check_done_snippet():
        """Splice body recording that the real checker finished before
        the publication hold — publication-hold controls must not pass
        on an expiry that landed before checking."""
        return ('\t\t// test-only: record that the real check finished '
                'before the publication hold\n'
                '\t\tif mf := os.Getenv("R2_T04_MARKER"); mf != "" {\n'
                '\t\t\tif f, merr := os.OpenFile(mf, os.O_APPEND|os.O_CREATE|'
                'os.O_WRONLY, 0o644); merr == nil {\n'
                '\t\t\t\tfmt.Fprintf(f, "check done pid=%d\\n", os.Getpid())\n'
                '\t\t\t\t_ = f.Close()\n'
                '\t\t\t}\n'
                '\t\t}\n')

    def fifo_fixture(self):
        """fntime2: mode m1 is self-contained and certifies narrowly; mode
        m2 imports example.test/fntime2/dep whose export bytes the test
        withholds behind a FIFO; mode m3 stays unexamined. Hand-enumerated
        per-declaration floor obligations below are derived from this
        fixture text alone, never from the helper's own fallback."""
        module = self.write_module('fntime2', {
            'shared.go': ('//go:build !m2\n\npackage fntime2\n\n'
                          'type runner interface{ Dispatch() bool }\n\n'
                          'func Always(r runner) bool { return r.Dispatch() }\n\n'
                          'func Shadowed() bool { Dispatch := true; return Dispatch }\n\n'
                          'func Dispatch(n int) bool { return n > 0 }\n'),
            'm1only.go': ('//go:build m1\n\npackage fntime2\n\n'
                          'func First() bool { return Dispatch(1) }\n'),
            'blocked.go': ('//go:build m2\n\npackage fntime2\n\n'
                           'import "example.test/fntime2/dep"\n\n'
                           'func Second() bool { return dep.Open() }\n\n'
                           'func SecondShadow() bool { Dispatch := true; return Dispatch }\n'),
            'm3only.go': ('//go:build m3\n\npackage fntime2\n\n'
                          'func Third() bool { return Dispatch(3) }\n'),
            'dep/dep.go': ('package dep\n\nfunc Open() bool { return true }\n\n'
                           'func Nearby() bool { return true }\n'),
        })
        env = self.go_env()
        for tags in ('m1', 'm2'):
            argv = ['go', 'list', '-deps', '-export', '-test']
            if tags != '':
                argv += ['-tags', tags]
            subprocess.run(argv + ['.'], cwd=module, capture_output=True,
                           env=env, timeout=100, check=True)
        return module

    def deadline_copy(self, name, budget_ms=None, fifo=None, source=None,
                      splices=()):
        """Isolated test-only copy of the helper. budget_ms shortens the
        analysis deadline; fifo redirects one dependency's export file to
        a FIFO path; splices are exact-count source edits."""
        text = self.helper.read_text() if source is None else source
        for old, new_text in splices:
            self.assertEqual(text.count(old), 1, f'splice anchor not unique: {old!r}')
            text = text.replace(old, new_text)
        if budget_ms is not None:
            self.assertEqual(text.count('const analysisBudget = 90 * time.Second'), 1)
            text = text.replace(
                'const analysisBudget = 90 * time.Second',
                f'const analysisBudget = {budget_ms} * time.Millisecond')
        if fifo is not None:
            dep, path = fifo
            anchor = '\tif len(exports) == 0 {'
            inject = ('\t// test-only: withhold one dependency\'s export bytes '
                      'behind a FIFO\n'
                      f'\tif exports["{dep}"] != "" {{\n'
                      f'\t\texports["{dep}"] = "{path}"\n'
                      '\t}\n')
            self.assertEqual(text.count(anchor), 1)
            text = text.replace(anchor, inject + anchor)
        out = self.root / name
        out.write_text(text)
        return out

    def drain_session(self, sid, term_wait=3.0, kill_wait=5.0):
        """Terminate and drain every process group still owned by the
        guard session: TERM each session-owned group, bounded-wait for
        /proc to show it gone, then KILL what remains and require
        actual removal. Zombies are already-terminated processes and
        are ignored; groups outside the session are never touched."""
        def owned_groups():
            groups = {}
            for pid in self.session_members(sid):
                try:
                    with open(f'/proc/{pid}/stat') as stat:
                        fields = stat.read().rsplit(')', 1)[1].split()
                    if len(fields) > 2 and fields[0] != 'Z':
                        groups.setdefault(int(fields[2]), []).append(pid)
                except (OSError, ValueError, IndexError):
                    continue
            return groups

        for sig, wait in ((signal.SIGTERM, term_wait),
                          (signal.SIGKILL, kill_wait)):
            deadline = time.monotonic() + wait
            while True:
                groups = owned_groups()
                if not groups:
                    return
                for pgid in groups:
                    try:
                        os.killpg(pgid, sig)
                    except (ProcessLookupError, PermissionError):
                        pass
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
        remaining = owned_groups()
        if remaining:
            raise AssertionError(
                f'guard session {sid} still has live members: {remaining}')

    def _drain_guard_sids(self):
        failures = []
        for sid in self._guard_sids:
            try:
                self.drain_session(sid)
            except AssertionError as exc:
                failures.append(exc)
        if failures:
            raise AssertionError(
                'guard sessions with live members after the teardown '
                'drain: '
                + '; '.join(str(failure) for failure in failures))

    def guarded_helper(self, argv, cwd, env, request, timeout):
        """Independent outer safety guard: one session per run. Every
        descendant the launched command owns stays in that session in
        however many process groups it created. On timeout the whole
        session is drained — TERM, then KILL, with actual /proc
        completion checks — before the TimeoutExpired surfaces as
        evidence; on normal return the tests observe the product's own
        cleanup first, and teardown drains what is left, failing
        loudly if any session-owned group survives."""
        proc = subprocess.Popen(argv, cwd=str(cwd), text=True, env=env,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        self.last_sid = proc.pid
        self._guard_sids.append(proc.pid)
        try:
            deadline = time.monotonic() + timeout
            try:
                out, err = proc.communicate(request, timeout=timeout)
                if proc.poll() is None:
                    # A descendant closing every inherited pipe lets
                    # communicate() return while the leader still runs;
                    # the guard keeps waiting for the leader itself,
                    # bounded by the same deadline.
                    proc.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                self.drain_session(proc.pid)
                # drain_session removed every non-zombie session group;
                # a leader that still cannot be reaped inside this bound
                # is a real guard failure and stays visible here.
                proc.wait(timeout=10)
                raise
            return subprocess.CompletedProcess(argv, proc.returncode, out, err)
        finally:
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass

    def guarded_go_run(self, module, env, path, request, timeout=100):
        """HARNESS-GUARD-01: the only launcher TIME01-style helper runs
        go through — never a bare Popen with an unguarded communicate.
        The exact production request is delivered to the exact helper
        file; on success the real guard session id from self.last_sid is
        returned beside the parsed rows, so the caller can assert the
        product's own cleanup removed every session descendant before
        teardown. On timeout the guard drains the whole owned session
        before the TimeoutExpired surfaces."""
        run = self.guarded_helper(['go', 'run', str(path)], cwd=module,
                                  env=env, request=request, timeout=timeout)
        self.assertEqual(run.returncode, 0, run.stderr[:400])
        return self.last_sid, {row['path']: row for row in json.loads(run.stdout)}

    def fifo_writer(self, path):
        """Fixture-owned FIFO writer: opening for write blocks until the
        helper's real gc importer opens the read end — that is the
        handshake — then the write end is held open without ever
        supplying export bytes, until the test releases it."""
        state = {'fd': None, 'connected': None}
        release = threading.Event()

        def run():
            try:
                fd = os.open(path, os.O_WRONLY)
                state['fd'] = fd
                state['connected'] = time.monotonic()
                release.wait(180)
                os.close(fd)
            except OSError:
                pass

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return state, release, thread

    def stop_fifo_writer(self, state, release, thread):
        release.set()
        if state['fd'] is None and state['connected'] is None:
            # A helper killed before connecting leaves the writer blocked
            # in open; a brief non-blocking read end completes it.
            try:
                fd = os.open(state['path'], os.O_RDONLY | os.O_NONBLOCK)
                os.close(fd)
            except OSError:
                pass
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())

    def session_members(self, sid):
        members = []
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            try:
                with open(f'/proc/{entry}/stat') as stat:
                    fields = stat.read().rsplit(')', 1)[1].split()
                if len(fields) > 3 and int(fields[3]) == sid:
                    members.append(int(entry))
            except (OSError, ValueError, IndexError):
                continue
        return members

    @staticmethod
    def proc_state(pid):
        """Live-process discriminator: the scheduler state from
        /proc/<pid>/stat, '' when the pid is gone. Zombies report as
        'Z' — kill(pid, 0) alone cannot distinguish them from a live
        escapee."""
        try:
            with open(f'/proc/{pid}/stat') as stat:
                fields = stat.read().rsplit(')', 1)[1].split()
            return fields[0]
        except (OSError, IndexError):
            return ''

    def assert_deadline_floor(self, rows, expected_paths, notes=True):
        """Complete conservative result: every requested row survives
        with the deadline note and the hand-enumerated name-based floor
        obligations that hold for every caller's exact requested rows —
        including the shadowed name a narrow mode had proved local and
        the selector reference the interface call owes. Case-specific
        obligations (m3only, the blocked foreign selector) belong to the
        requesting test; the sorted row-set assertion below already
        rejects an unexpectedly missing required path."""
        self.assertEqual(sorted(rows), sorted(expected_paths), sorted(rows))
        for path, row in rows.items():
            if notes:
                self.assertTrue(any('analysis deadline exceeded' in note
                                    for note in row.get('resolution') or []),
                                (path, row.get('resolution')))
        shadowed = self.unit(rows['shared.go'], 'Shadowed')
        self.assertIn('Dispatch', shadowed.get('refs') or [], shadowed)
        self.assertIn('Dispatch', self.unit(rows['m1only.go'], 'First').get('refs') or [])
        self.assertIn('Dispatch', self.unit(rows['shared.go'], 'Always').get('selrefs') or [])

    def test_time02_deadline_during_check_bounds_termination(self):
        """TIME-02: the shared deadline expiring inside the synchronous
        type check — blocked reading a dependency's real export data
        through a FIFO — must terminate the helper itself. The handshake
        (the writer's blocking open returning) proves the real gc
        importer reached the export read before expiry, never go list
        and never a fake sleep; the production budget, request and
        algorithm run unchanged in the isolated copy. The fixed helper
        emits one complete conservative document and self-exits within
        the deadline plus output allowance while the FIFO stays blocked.
        Against the current unfixed source this control fails by the
        outer guard terminating a helper that cannot self-exit — the
        explicit original-defect evidence."""
        module = self.fifo_fixture()
        fifo = self.root / 'dep.fifo'
        os.mkfifo(fifo)
        paths = ['shared.go', 'm1only.go', 'blocked.go', 'm3only.go']
        modes = [['m1'], ['m2'], ['m3']]
        request = json.dumps({'paths': paths, 'modes': modes})
        env = self.go_env()
        prime = self.deadline_copy('units-t02prime.go')
        # Prime the copy compile and the m1 listings: the m1 request has
        # no dep entry, so no FIFO reader ever appears.
        run = self.guarded_helper(['go', 'run', str(prime)], module, env,
                                  json.dumps({'paths': ['shared.go', 'm1only.go'],
                                              'modes': [['m1']]}), timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        repro = self.deadline_copy('units-t02repro.go', budget_ms=6000,
                                   fifo=('example.test/fntime2/dep', str(fifo)))
        state, release, thread = self.fifo_writer(fifo)
        state['path'] = str(fifo)
        start = time.monotonic()
        try:
            run = self.guarded_helper(['go', 'run', str(repro)], module, env,
                                      request, timeout=30)
        except subprocess.TimeoutExpired:
            self.fail('original defect reproduced: the helper could not '
                      'self-exit while its synchronous type check stayed '
                      'blocked reading export data (guard terminated the '
                      'session at 30s); connected='
                      f"{bool(state['connected'])}")
        finally:
            self.stop_fifo_writer(state, release, thread)
        wall = time.monotonic() - start
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        # Handshake before expiry: the real Check reached the export read
        # well inside the shortened deadline.
        self.assertIsNotNone(state['connected'],
                             'no reader ever opened the FIFO export data')
        self.assertLess(state['connected'] - start, 6.0,
                        'export read reached after the deadline expired')
        # Self-exit while the FIFO is still withheld: bounded termination
        # with the deadline-plus-output allowance, before any guard.
        self.assertLessEqual(wall, 6.0 + 3.0,
                             f'helper exited {wall:.1f}s after start')
        self.assertIsNotNone(state['fd'], 'FIFO writer lost its write end')
        rows = {row['path']: row for row in json.loads(run.stdout)}
        self.assert_deadline_floor(rows, paths)
        self.assertIn('Dispatch', self.unit(rows['m3only.go'], 'Third').get('refs') or [])
        # Foreign selector never widens production refs. The floor's
        # name table (nameBasedReferences) deliberately carries explicit
        # import aliases only, so a default import contributes no local
        # reference: the floored Second.refs set is empty and the
        # selector-position Open lands in selrefs only. go/types places
        # the dep qualifier into Second.refs under real resolution —
        # pinned by the TIME-03 baseline.
        second = self.unit(rows['blocked.go'], 'Second')
        self.assertIn('Open', second.get('selrefs') or [], second)
        self.assertEqual(second.get('refs') or [], [], second)
        self.assertIn('Dispatch',
                      self.unit(rows['blocked.go'], 'SecondShadow').get('refs') or [])
        self.assertEqual(rows['shared.go']['matched'], [True, False, True])
        self.assertEqual(rows['m1only.go']['matched'], [True, False, False])
        self.assertEqual(rows['blocked.go']['matched'], [False, True, False])
        self.assertEqual(rows['m3only.go']['matched'], [False, False, True])
        # No abandoned helper or descendant survives the self-exit.
        time.sleep(1)
        members = self.session_members(self.last_sid)
        self.assertEqual(members, [], f'abandoned session descendants: {members}')

    def test_time02n_blocking_receive_negative(self):
        """TIME-02 negative: replacing only the deadline-select with a
        blocking receive of the real checker outcome must hang the
        helper on the withheld FIFO — the bounded-exit oracle then fails
        through the outer guard. Run against the fixed source."""
        fixed = self.helper.read_text()
        select_block = ('\tresult := checkOutcome{}\n'
                        '\tselect {\n'
                        '\tcase result = <-outcome:\n'
                        '\tcase <-ctx.Done():\n'
                        '\t}')
        self.assertIn(select_block, fixed, 'fixed deadline-select anchor missing')
        module = self.fifo_fixture()
        fifo = self.root / 'depneg.fifo'
        os.mkfifo(fifo)
        broken = self.deadline_copy(
            'units-t02neg.go', budget_ms=6000,
            fifo=('example.test/fntime2/dep', str(fifo)), source=fixed,
            splices=[(select_block, '\tresult := checkOutcome{}\n\tresult = <-outcome')])
        state, release, thread = self.fifo_writer(fifo)
        state['path'] = str(fifo)
        env = self.go_env()
        request = json.dumps({'paths': ['blocked.go'], 'modes': [['m2']]})
        start = time.monotonic()
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.guarded_helper(['go', 'run', str(broken)], module, env,
                                    request, timeout=30)
        finally:
            self.stop_fifo_writer(state, release, thread)
        # A startup hang that never reaches the real importer is not
        # this defect: the real gc importer must have connected to the
        # FIFO well inside the shortened budget before the expiry.
        self.assertIsNotNone(
            state['connected'],
            'timeout without the real importer ever connecting: startup '
            'TimeoutExpired alone is not the blocking-receive defect')
        self.assertLess(state['connected'] - start, 6.0,
                        'importer connected only after the deadline')

    def test_time03_deadline_last_mode_floors_entire_request(self):
        """TIME-03: expiry inside the LAST mode's check must floor the
        entire request, not only the blocked group's files — no later
        loop iteration exists to propagate the floor. A same-fixture
        baseline run (full budget, real export data) proves the earlier
        mode certified Shadowed narrowly and that applicability vectors
        and every static JSON field stay unchanged by the deadline run.
        Against the unfixed source this control fails through the outer
        guard, exactly like TIME-02."""
        module = self.fifo_fixture()
        paths = ['shared.go', 'm1only.go', 'blocked.go']
        modes = [['m1'], ['m2']]
        env = self.go_env()
        baseline_copy = self.deadline_copy('units-t03base.go')
        base = self.guarded_helper(['go', 'run', str(baseline_copy)], module, env,
                                   json.dumps({'paths': paths, 'modes': modes}),
                                   timeout=60)
        self.assertEqual(base.returncode, 0, base.stderr[-400:])
        base_rows = {row['path']: row for row in json.loads(base.stdout)}
        for path, row in base_rows.items():
            self.assertEqual(row.get('resolution') or [], [], (path, row.get('resolution')))
        self.assertNotIn('Dispatch',
                         self.unit(base_rows['shared.go'], 'Shadowed').get('refs') or [])
        # Real resolution places the imported dep qualifier in
        # Second.refs and keeps the foreign selector Open out of both
        # refs and selrefs; the floored placement of dep is the import
        # unit, asserted by TIME-02.
        base_second = self.unit(base_rows['blocked.go'], 'Second')
        self.assertEqual(base_second.get('refs') or [], ['dep'], base_second)
        self.assertNotIn('Open', base_second.get('refs') or [], base_second)
        self.assertNotIn('Open', base_second.get('selrefs') or [], base_second)
        fifo = self.root / 'deplast.fifo'
        os.mkfifo(fifo)
        repro = self.deadline_copy('units-t03repro.go', budget_ms=6000,
                                   fifo=('example.test/fntime2/dep', str(fifo)))
        state, release, thread = self.fifo_writer(fifo)
        state['path'] = str(fifo)
        start = time.monotonic()
        try:
            run = self.guarded_helper(['go', 'run', str(repro)], module, env,
                                      json.dumps({'paths': paths, 'modes': modes}),
                                      timeout=30)
        except subprocess.TimeoutExpired:
            self.fail('original defect reproduced: helper could not self-exit '
                      'with the last mode blocked on withheld export data')
        finally:
            self.stop_fifo_writer(state, release, thread)
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        self.assertLessEqual(time.monotonic() - start, 9.0)
        # Real-check boundary: the importer connected inside the budget
        # and the expiry landed at the synchronous check, never during
        # go list — a listing failure would carry a different note.
        self.assertIsNotNone(state['connected'],
                             'no importer connection: expiry during '
                             'startup is not the last-mode check defect')
        self.assertLess(state['connected'] - start, 6.0)
        rows = {row['path']: row for row in json.loads(run.stdout)}
        self.assert_deadline_floor(rows, paths)
        for path, row in rows.items():
            self.assertFalse(
                any('mode go list failed' in note
                    for note in row.get('resolution') or []),
                (path, row.get('resolution')))
        # Static shape identical to the baseline: modes, applicability
        # vectors and every per-unit field except refs/selrefs.
        for path, row in rows.items():
            self.assertEqual(row['matched'], base_rows[path]['matched'], path)
            base_out = {k: v for k, v in base_rows[path].items()
                        if k not in ('units', 'resolution')}
            out = {k: v for k, v in row.items() if k not in ('units', 'resolution')}
            self.assertEqual(out, base_out, path)
            base_units = [{k: v for k, v in u.items()
                          if k not in ('refs', 'selrefs', 'floor_refs')}
                          for u in base_rows[path]['units']]
            units = [{k: v for k, v in u.items()
                     if k not in ('refs', 'selrefs', 'floor_refs')}
                     for u in row['units']]
            self.assertEqual(units, base_units, path)

    def test_time03n_missing_after_loop_propagation_negative(self):
        """TIME-03 negative: disabling only the after-loop deadline
        propagation keeps the blocked group's floor but loses the
        request-wide floor for the earlier mode's narrow results — the
        hand-enumerated obligations fail with the helper still exiting
        cleanly. Run against the fixed source."""
        fixed = self.helper.read_text()
        gate = ('\tif ctx.Err() != nil && !deadlineFloored {\n'
                '\t\tmarkFloor(res, files, nil, '
                '"resolution-fallback: analysis deadline exceeded")\n'
                '\t}')
        self.assertIn(gate, fixed, 'after-loop propagation anchor missing')
        module = self.fifo_fixture()
        fifo = self.root / 'deplastneg.fifo'
        os.mkfifo(fifo)
        broken = self.deadline_copy(
            'units-t03neg.go', budget_ms=6000,
            fifo=('example.test/fntime2/dep', str(fifo)), source=fixed,
            splices=[(gate, '\tif false && ctx.Err() != nil && !deadlineFloored {\n'
                            '\t\tmarkFloor(res, files, nil, '
                            '"resolution-fallback: analysis deadline exceeded")\n'
                            '\t}')])
        env = self.go_env()
        request = json.dumps({'paths': ['shared.go', 'm1only.go', 'blocked.go'],
                              'modes': [['m1'], ['m2']]})
        state, release, thread = self.fifo_writer(fifo)
        state['path'] = str(fifo)
        try:
            run = self.guarded_helper(['go', 'run', str(broken)], module, env,
                                      request, timeout=30)
        finally:
            self.stop_fifo_writer(state, release, thread)
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        rows = {row['path']: row for row in json.loads(run.stdout)}
        # The intended violation: the earlier mode's narrow result for
        # Shadowed survived the last-mode expiry, and shared.go carries
        # no request-wide deadline note.
        shadowed = self.unit(rows['shared.go'], 'Shadowed')
        self.assertNotIn('Dispatch', shadowed.get('refs') or [], shadowed)
        self.assertFalse(any('analysis deadline exceeded' in note
                             for note in rows['shared.go'].get('resolution') or []),
                         rows['shared.go'].get('resolution'))
        self.assertTrue(any('analysis deadline exceeded' in note
                            for note in rows['blocked.go'].get('resolution') or []))

    def test_time03_floor_refs_spellings_pinned(self):
        """TIME-03-FLOOR-01: the deadline floor is a distinct evidence
        channel with exact hand-enumerated spellings, not a reporting
        side effect. A full-budget baseline over the same fixture leaves
        every floor_refs empty; the deadline run regains exactly the
        spellings the fixture text supports — including the shadowed
        Dispatch, the interface twin and the file-scope type unit — and
        a splice disabling only the markFloor flag collapses every floor
        spelling and its refs union while the deadline notes and the
        surviving checked evidence stay: the flag drives the channel."""
        module = self.fifo_fixture()
        paths = ['shared.go', 'm1only.go', 'blocked.go']
        request = json.dumps({'paths': paths, 'modes': [['m1'], ['m2']]})
        env = self.go_env()

        # Hand-enumerated floor obligations, derived from the fixture
        # text alone: nameBasedReferences matches package-level names
        # without scope analysis, so shadowed locals still count, while
        # the default dep import and the foreign Open contribute
        # nothing. The measured helper output below must match this
        # enumeration, never define it.
        expected = {
            ('shared.go', ''): ['Dispatch', 'runner'],
            ('shared.go', 'Always'): ['Dispatch', 'runner'],
            ('shared.go', 'Dispatch'): [],
            ('shared.go', 'Shadowed'): ['Dispatch'],
            ('m1only.go', 'First'): ['Dispatch'],
            ('blocked.go', ''): [],
            ('blocked.go', 'Second'): [],
            ('blocked.go', 'SecondShadow'): ['Dispatch'],
        }

        def spellings(rows):
            got = {}
            for path, row in rows.items():
                for unit in row['units']:
                    got[(path, unit['name'])] = unit.get('floor_refs') or []
            return got

        # Checked leg: the same request with real export data certifies
        # every requested unit and leaves the floor channel silent.
        baseline_copy = self.deadline_copy('units-f6base.go')
        base = self.guarded_helper(['go', 'run', str(baseline_copy)], module,
                                   env, request, timeout=60)
        self.assertEqual(base.returncode, 0, base.stderr[-400:])
        base_rows = {row['path']: row for row in json.loads(base.stdout)}
        for path, row in base_rows.items():
            self.assertEqual(row.get('resolution') or [], [],
                             (path, row.get('resolution')))
            for decl in row['units']:
                self.assertEqual(decl.get('floor_refs') or [], [],
                                 (path, decl['name']))
        shadowed = self.unit(base_rows['shared.go'], 'Shadowed')
        self.assertEqual(shadowed.get('refs') or [], [],
                         'checked Shadowed must stay narrow')
        second = self.unit(base_rows['blocked.go'], 'Second')
        self.assertEqual(second.get('refs') or [], ['dep'], second)

        # Floored leg: the expiry floors the whole request and the
        # spellings match the enumeration exactly — no missing, extra
        # or invented obligation. Every floor spelling is also in refs,
        # and the surviving checked evidence (Always's interface selref,
        # the selector-position Open) is untouched beside the floor.
        fifo = self.root / 'f6floor.fifo'
        os.mkfifo(fifo)
        floored_copy = self.deadline_copy(
            'units-f6floor.go', budget_ms=6000,
            fifo=('example.test/fntime2/dep', str(fifo)))
        state, release, thread = self.fifo_writer(fifo)
        state['path'] = str(fifo)
        try:
            run = self.guarded_helper(['go', 'run', str(floored_copy)], module,
                                      env, request, timeout=30)
        finally:
            self.stop_fifo_writer(state, release, thread)
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        rows = {row['path']: row for row in json.loads(run.stdout)}
        self.assertEqual(spellings(rows), expected)
        for path, row in rows.items():
            self.assertTrue(any('analysis deadline exceeded' in note
                                for note in row.get('resolution') or []),
                            (path, row.get('resolution')))
        shadowed = self.unit(rows['shared.go'], 'Shadowed')
        self.assertEqual(shadowed.get('refs') or [], ['Dispatch'], shadowed)
        self.assertIn('Dispatch',
                      self.unit(rows['shared.go'], 'Always').get('selrefs') or [])
        second = self.unit(rows['blocked.go'], 'Second')
        self.assertEqual(second.get('floor_refs') or [], [], second)
        self.assertIn('Open', second.get('selrefs') or [], second)

        # Negative marker: disabling only the markFloor flag — the note
        # stays and the per-declaration entries still exist — collapses
        # every floor spelling and the unioned refs with it, while the
        # surviving checked evidence is untouched. The flag, not the
        # note or a reporting path, is the channel's driver.
        spliced = self.deadline_copy(
            'units-f6nofloor.go', budget_ms=6000,
            fifo=('example.test/fntime2/dep', str(fifo)),
            splices=[('d.floor = true', '_ = d.floor')])
        state, release, thread = self.fifo_writer(fifo)
        state['path'] = str(fifo)
        try:
            run = self.guarded_helper(['go', 'run', str(spliced)], module,
                                      env, request, timeout=30)
        finally:
            self.stop_fifo_writer(state, release, thread)
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        rows = {row['path']: row for row in json.loads(run.stdout)}
        self.assertEqual(spellings(rows), {key: [] for key in expected})
        for path, row in rows.items():
            self.assertTrue(any('analysis deadline exceeded' in note
                                for note in row.get('resolution') or []),
                            (path, row.get('resolution')))
        shadowed = self.unit(rows['shared.go'], 'Shadowed')
        self.assertEqual(shadowed.get('refs') or [], [],
                         'floor flag removed but refs stayed widened')
        self.assertIn('Dispatch',
                      self.unit(rows['shared.go'], 'Always').get('selrefs') or [])
        # Second had no checked evidence at all: its perDecl entry is
        # the empty one markFloor created, so its floor-sourced selrefs
        # collapse with the flag. Always is the surviving checked-
        # evidence control above.
        self.assertEqual(
            self.unit(rows['blocked.go'], 'Second').get('selrefs') or [], [],
            'floor flag removed but Second kept floor-sourced selrefs')

    def test_time04_late_check_outcome_discarded(self):
        """TIME-04: a real check that completes successfully but
        publishes its outcome only after the shared deadline expired
        must be discarded — the parent floors instead of certifying, and
        never waits for the held outcome. Requires the fixed
        deadline-select structure; against the unfixed source this
        control fails on the missing anchor itself."""
        fixed = self.helper.read_text()
        send = '\t\toutcome <- checkOutcome{pkg: pkg, done: true}'
        self.assertEqual(fixed.count(send), 1,
                         'late-hold splice anchor missing: fixed deadline '
                         'structure required')
        module = self.fifo_fixture()
        marker = self.root / 't04-check-done.marker'
        env = self.go_env(R2_T04_MARKER=str(marker))
        held = self.deadline_copy(
            'units-t04hold.go', budget_ms=1500, source=fixed,
            splices=[(send, '\t\t// test-only hold: publication waits past '
                            'the deadline\n' + self.check_done_snippet() +
                            '\t\ttime.Sleep(4 * time.Second)\n' + send)])
        request = json.dumps({'paths': ['shared.go', 'm1only.go'], 'modes': [['m1']]})
        # Both runs complete through the expiry path; the first primes
        # the copy compile, the second is measured.
        self.guarded_helper(['go', 'run', str(held)], module, env, request, timeout=30)
        marker.unlink(missing_ok=True)
        start = time.monotonic()
        run = self.guarded_helper(['go', 'run', str(held)], module, env, request,
                                  timeout=30)
        wall = time.monotonic() - start
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        # The checker really finished before the expiry: this is a
        # publication hold, not an expiry-before-checking scenario.
        self.assertIn('check done', marker.read_text())
        # The parent did NOT wait for the held outcome (publication is
        # 4s past a check that finished well inside the 1.5s budget).
        self.assertLess(wall, 3.5, f'helper waited {wall:.1f}s for the held outcome')
        rows = {row['path']: row for row in json.loads(run.stdout)}
        self.assert_deadline_floor(rows, ['shared.go', 'm1only.go'])

    def test_time04n_blocking_receive_waits_and_certifies_negative(self):
        """TIME-04 combined-net mutant: blocking receive, removed
        post-receipt discard gate and request-wide propagation
        pre-disarmed together let the parent wait out the held outcome
        and certify it after expiry — the wait is the
        bounded-termination defect and the certified rows (real refs,
        Shadowed narrow, no request-wide floor) prove the whole
        discard net is gone. This control does not isolate the receipt
        guard alone: TIME-02N isolates the blocking receive and
        TIME-03N the request-wide propagation."""
        fixed = self.helper.read_text()
        send = '\t\toutcome <- checkOutcome{pkg: pkg, done: true}'
        select_block = ('\tresult := checkOutcome{}\n'
                        '\tselect {\n'
                        '\tcase result = <-outcome:\n'
                        '\tcase <-ctx.Done():\n'
                        '\t}')
        guard = ('\tif !result.done || ctx.Err() != nil {\n'
                 '\t\tmarkFloor(res, group.items, nil, '
                 '"resolution-fallback: analysis deadline exceeded")\n'
                 '\t\treturn false\n'
                 '\t}')
        floored_decl = 'deadlineFloored := false'
        self.assertEqual(fixed.count(send), 1)
        self.assertEqual(fixed.count(select_block), 1)
        self.assertEqual(fixed.count(guard), 1)
        self.assertEqual(fixed.count(floored_decl), 1)
        module = self.fifo_fixture()
        marker = self.root / 't04n-check-done.marker'
        env = self.go_env(R2_T04_MARKER=str(marker))
        broken = self.deadline_copy(
            'units-t04neg.go', budget_ms=1500, source=fixed,
            splices=[(send, self.check_done_snippet()
                      + '\t\ttime.Sleep(4 * time.Second)\n' + send),
                      (select_block,
                       '\tresult := checkOutcome{}\n\tresult = <-outcome'),
                      (guard, ''),
                      (floored_decl, 'deadlineFloored := true')])
        request = json.dumps({'paths': ['shared.go', 'm1only.go'], 'modes': [['m1']]})
        self.guarded_helper(['go', 'run', str(broken)], module, env, request, timeout=30)
        marker.unlink(missing_ok=True)
        start = time.monotonic()
        run = self.guarded_helper(['go', 'run', str(broken)], module, env, request, timeout=30)
        wall = time.monotonic() - start
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        # The checker really finished before the expiry: the mutant
        # certified a completed check late, never a never-run one.
        self.assertIn('check done', marker.read_text())
        # The intended violation: the parent waited out the held outcome
        # instead of self-exiting at the deadline.
        self.assertGreaterEqual(wall, 3.5, 'broken variant did not wait for the hold')
        rows = {row['path']: row for row in json.loads(run.stdout)}
        self.assertEqual(sorted(rows), ['m1only.go', 'shared.go'])
        # No floor anywhere: the independent expected result is an
        # empty resolution list; the actual value is diagnostic only.
        for row in rows.values():
            self.assertEqual(row.get('resolution') or [], [], row.get('resolution'))
        # The late outcome was certified for real: Shadowed's local
        # Dispatch variable shadows the package function, so a genuine
        # type-check resolves no Dispatch reference — a floored row
        # would carry the conservative fallback reference instead.
        shadowed = self.unit(rows['shared.go'], 'Shadowed')
        self.assertNotIn('Dispatch', shadowed.get('refs') or [], shadowed)

    def test_time05_race_enabled_deadline_controls(self):
        """TIME-05: the timeout and late-publication controls under the
        race detector — worker-owned checker state must produce no data
        races while the parent floors, discards and exits. Race-runtime
        overhead is covered by widened exit allowances, never by
        relaxing an oracle."""
        fixed = self.helper.read_text()
        send = '\t\toutcome <- checkOutcome{pkg: pkg, done: true}'
        self.assertEqual(fixed.count(send), 1)
        module = self.fifo_fixture()
        env = self.go_env()
        fifo = self.root / 'deprace.fifo'
        os.mkfifo(fifo)
        repro = self.deadline_copy('units-t05race.go', budget_ms=6000,
                                   fifo=('example.test/fntime2/dep', str(fifo)),
                                   source=fixed)
        prime = self.guarded_helper(
            ['go', 'run', '-race', str(repro)], module, env,
            json.dumps({'paths': ['shared.go', 'm1only.go'], 'modes': [['m1']]}),
            timeout=90)
        self.assertEqual(prime.returncode, 0, prime.stderr[-600:])
        state, release, thread = self.fifo_writer(fifo)
        state['path'] = str(fifo)
        paths = ['shared.go', 'm1only.go', 'blocked.go', 'm3only.go']
        start = time.monotonic()
        try:
            run = self.guarded_helper(
                ['go', 'run', '-race', str(repro)], module, env,
                json.dumps({'paths': paths, 'modes': [['m1'], ['m2'], ['m3']]}),
                timeout=40)
        finally:
            self.stop_fifo_writer(state, release, thread)
        self.assertEqual(run.returncode, 0, run.stderr[-600:])
        self.assertNotIn('DATA RACE', run.stderr)
        self.assertLessEqual(time.monotonic() - start, 6.0 + 3.0 + 2.5)
        # Same real-check boundary as TIME-02/-03, under race runtime:
        # the importer connected inside the budget and the expiry
        # landed at the synchronous check, never during go list.
        self.assertIsNotNone(state['connected'],
                             'race leg expired before the importer '
                             'connected')
        self.assertLess(state['connected'] - start, 6.0)
        rows = {row['path']: row for row in json.loads(run.stdout)}
        self.assert_deadline_floor(rows, paths)
        for path, row in rows.items():
            self.assertFalse(
                any('mode go list failed' in note
                    for note in row.get('resolution') or []),
                (path, row.get('resolution')))

        race_marker = self.root / 't05-check-done.marker'
        hold_env = self.go_env(R2_T04_MARKER=str(race_marker))
        held = self.deadline_copy(
            'units-t05hold.go', budget_ms=1500, source=fixed,
            splices=[(send, self.check_done_snippet()
                      + '\t\ttime.Sleep(4 * time.Second)\n' + send)])
        request = json.dumps({'paths': ['shared.go', 'm1only.go'], 'modes': [['m1']]})
        self.guarded_helper(['go', 'run', '-race', str(held)], module, hold_env,
                            request, timeout=90)
        race_marker.unlink(missing_ok=True)
        start = time.monotonic()
        hold_run = self.guarded_helper(['go', 'run', '-race', str(held)], module,
                                        hold_env, request, timeout=40)
        self.assertEqual(hold_run.returncode, 0, hold_run.stderr[-600:])
        self.assertNotIn('DATA RACE', hold_run.stderr)
        self.assertLess(time.monotonic() - start, 4.0)
        # Same check-completion marker as TIME-04, under race runtime.
        self.assertIn('check done', race_marker.read_text())
        rows = {row['path']: row for row in json.loads(hold_run.stdout)}
        self.assert_deadline_floor(rows, ['shared.go', 'm1only.go'])

    def test_time06_deadline_kills_live_golist_descendant_group(self):
        """TIME-06: with a go-command wrapper spawning a real long-lived
        descendant inside the listing's process group, a deadline that
        expires while go list is genuinely active must leave neither the
        leader (waited by the helper) nor the descendant alive — checked
        before any test cleanup, through the wrapper's PID handshake.
        The note proves the listing itself was terminated. The prime leg
        additionally proves the product's post-Run owned-group cleanup:
        a successful listing must reclaim its reported descendants with
        no harness-side kill."""
        module = self.root / 'fnlive'
        module.mkdir(parents=True)
        (module / 'go.mod').write_text('module example.test/fnlive\n\ngo 1.27\n')
        (module / 'shared.go').write_text(
            'package fnlive\n\nfunc Shadowed() bool { Dispatch := true; return Dispatch }\n\n'
            'func Dispatch(n int) bool { return n > 0 }\n')
        big = ['//go:build slow', '', f'// nonce {os.urandom(8).hex()}', 'package fnlive', '']
        big += [f'func F{i}() int {{ return {i} }}' for i in range(80000)]
        (module / 'big.go').write_text('\n'.join(big) + '\n')
        wrapper = self.root / 'wrapbin'
        wrapper.mkdir()
        real_go = shutil.which('go')
        self.assertIsNotNone(real_go)
        pidfile = self.root / 'descendants.pid'
        sidecar = self.root / 't06-sidecar.log'
        wrapper_go = wrapper / 'go'
        wrapper_go.write_text(
            '#!/bin/sh\n'
            '# Unconditional invocation marker: sidecar evidence of which\n'
            '# executable actually served each go call.\n'
            'if [ -n "$R2_T06_SIDECAR" ]; then\n'
            "  { echo \"wrapper pid=$$ ppid=$(ps -o ppid= -p $$ 2>/dev/null | tr -d ' ') argv=$*\"\n"
            '    echo "  R2_DESCENDANT_FILE=${R2_DESCENDANT_FILE:-<unset>}"; } >> "$R2_T06_SIDECAR"\n'
            'fi\n'
            'if [ -n "$R2_DESCENDANT_FILE" ]; then\n'
            '  sleep 600 >/dev/null 2>&1 </dev/null &\n'
            '  echo $! >> "$R2_DESCENDANT_FILE"\n'
            'fi\n'
            f'exec {real_go} "$@"\n')
        wrapper_go.chmod(0o755)
        env = self.go_env(
            PATH=f'{wrapper}{os.pathsep}{os.environ["PATH"]}',
            R2_T06_SIDECAR=str(sidecar), R2_T06_WRAPPER=str(wrapper_go),
            R2_T06_DESCENDANTS=str(pidfile))
        source = self.helper.read_text()
        startline = '\tif err := cmd.Start(); err != nil {'
        waitline = '\n\twerr := cmd.Wait()\n'
        self.assertEqual(source.count(startline), 1,
                         'listing Start anchor missing')
        self.assertEqual(source.count(waitline), 1,
                         'post-observation Wait anchor missing')
        # Test-only launch binding: record the PATH-resolved command first
        # (root-cause evidence), then bind the nested listing explicitly to
        # the wrapper executable and hand it the descendant contract before
        # Start. PATH interception alone is not trusted; the real listing
        # arguments stay unchanged, and the completion record moves after
        # the production single Wait.
        bind = (
            '\t// test-only: record the resolved launch contract\n'
            '\tif sc := os.Getenv("R2_T06_SIDECAR"); sc != "" {\n'
            '\t\tif f, ferr := os.OpenFile(sc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); ferr == nil {\n'
            '\t\t\tfmt.Fprintf(f, "listing pid=%d ppid=%d resolved_cmd_path=%s cmd_args=%v\\n",\n'
            '\t\t\t\tos.Getpid(), os.Getppid(), cmd.Path, cmd.Args)\n'
            '\t\t\t_ = f.Close()\n'
            '\t\t}\n'
            '\t}\n'
            '\tcmd.Path = os.Getenv("R2_T06_WRAPPER")\n'
            '\tcmd.Env = append(os.Environ(), "R2_DESCENDANT_FILE="+os.Getenv("R2_T06_DESCENDANTS"))\n')
        waitlog = (
            '\tif sc := os.Getenv("R2_T06_SIDECAR"); sc != "" {\n'
            '\t\tif f, ferr := os.OpenFile(sc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); ferr == nil {\n'
            '\t\t\tfmt.Fprintf(f, "listing run_err=%v ctx_err=%v\\n", werr, ctx.Err())\n'
            '\t\t\t_ = f.Close()\n'
            '\t\t}\n'
            '\t}\n')
        t06_splices = [(startline, bind + startline),
                       (waitline, waitline + waitlog)]
        copy = self.deadline_copy('units-t06live.go', budget_ms=2500,
                                  source=source, splices=t06_splices)
        request = json.dumps({'paths': ['shared.go', 'big.go'], 'modes': [['slow']]})
        leaks = set()
        try:
            # Prime: a separate wide-budget copy completes the real listing
            # successfully; the product's post-Run owned-group cleanup must
            # already have reclaimed every descendant the wrapper reported —
            # checked before any harness-side kill.
            prime_copy = self.deadline_copy('units-t06prime.go', budget_ms=20000,
                                            source=source, splices=t06_splices)
            prime = self.guarded_helper(['go', 'run', str(prime_copy)], module, env,
                                        request, timeout=90)
            self.assertEqual(prime.returncode, 0, prime.stderr[-400:])
            prows = {row['path']: row for row in json.loads(prime.stdout)}
            for path, row in prows.items():
                self.assertFalse(
                    any('mode go list failed' in note
                        for note in row.get('resolution') or []),
                    f'{path}: {row.get("resolution")}')
            side = sidecar.read_text() if sidecar.exists() else ''
            # The nested go list resolved the wrapper, received the
            # descendant contract and completed successfully.
            self.assertIn(f'R2_DESCENDANT_FILE={pidfile}', side,
                          'nested go list never received the wrapper contract')
            self.assertIn('run_err=<nil>', side,
                          'no successful wrapper-fronted listing recorded')
            reported = pidfile.read_text().split() if pidfile.exists() else []
            self.assertTrue(reported, 'wrapper never reported a prime descendant')
            leaks.update(reported)
            gone_by = time.monotonic() + 5
            for pid in reported:
                while True:
                    try:
                        os.kill(int(pid), 0)
                    except (ProcessLookupError, ValueError):
                        break
                    self.assertLess(time.monotonic(), gone_by,
                                    f'prime descendant {pid} outlived the '
                                    'successful listing')
                    time.sleep(0.05)
            # Fresh nonce: the listing recompiles for seconds, so the 2.5s
            # deadline expires provably mid-child with a live descendant.
            pidfile.write_text('')
            sidecar.write_text('')
            big[2] = f'// nonce {os.urandom(8).hex()}'
            (module / 'big.go').write_text('\n'.join(big) + '\n')
            outcome = {}

            def launch():
                outcome['run'] = self.guarded_helper(['go', 'run', str(copy)], module,
                                                     env, request, timeout=30)

            runner = threading.Thread(target=launch)
            runner.start()
            handshake_deadline = time.monotonic() + 20
            while not (pidfile.exists() and pidfile.read_text().split()):
                self.assertTrue(runner.is_alive(),
                                'helper finished before any descendant handshake')
                self.assertLess(time.monotonic(), handshake_deadline,
                                'wrapper never reported a live descendant')
                time.sleep(0.05)
            leaks.update(pidfile.read_text().split())
            runner.join(timeout=60)
            run = outcome['run']
            self.assertEqual(run.returncode, 0, run.stderr[-400:])
            rows = {row['path']: row for row in json.loads(run.stdout)}
            self.assertTrue(any('mode go list failed: deadline exceeded' in note
                                for note in rows['big.go'].get('resolution') or []),
                            rows['big.go'].get('resolution'))
            # Every descendant the wrapper reported for the killed listing is
            # gone before any test cleanup, and the leader was waited for
            # (the helper exited through the deadline path above).
            gone_after = time.monotonic() + 5
            for pid in pidfile.read_text().split():
                while True:
                    try:
                        os.kill(int(pid), 0)
                    except ProcessLookupError:
                        break
                    self.assertLess(time.monotonic(), gone_after,
                                    f'descendant {pid} survived the group kill')
                    time.sleep(0.05)
            time.sleep(1)
            members = self.session_members(self.last_sid)
            self.assertEqual(members, [], f'abandoned session descendants: {members}')
        finally:
            for pid in leaks:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
            for name, path in (('t06-sidecar.log', sidecar),
                               ('t06-pidfile.txt', pidfile)):
                try:
                    shutil.copyfile(path, f'/tmp/opencode/{name}')
                except OSError:
                    pass

    def test_time06n_without_group_cancel_descendant_survives_negative(self):
        """TIME-06 negative: removing BOTH the deadline group
        cancellation and the post-Run owned-group cleanup leaves the
        wrapper's live descendant running after the leader was waited
        for — the control must catch the survivor, then clean it up."""
        cancel = ('\tcmd.Cancel = func() error {\n'
                  '\t\tmu.Lock()\n'
                  '\t\tdefer mu.Unlock()\n'
                  '\t\tif !armed {\n'
                  '\t\t\treturn os.ErrProcessDone\n'
                  '\t\t}\n'
                  '\t\t// Read the PID inside the callback: the context watcher can\n'
                  '\t\t// run before Start returns.\n'
                  '\t\tif cmd.Process == nil {\n'
                  '\t\t\treturn nil\n'
                  '\t\t}\n'
                  '\t\treturn syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)\n'
                  '\t}')
        cancel_leader_only = ('\tcmd.Cancel = func() error {\n'
                              '\t\t// test-only negative: leader-only termination\n'
                              '\t\t// with no group signal at either cleanup site,\n'
                              '\t\t// so the wrapper\'s reported descendant escapes.\n'
                              '\t\tif cmd.Process == nil {\n'
                              '\t\t\treturn nil\n'
                              '\t\t}\n'
                              '\t\treturn cmd.Process.Kill()\n'
                              '\t}')
        # The post-observation signal block only — the sigErr declaration
        # stays so the splice is a behavioral negative, not a compile error.
        cleanup = ('\tmu.Lock()\n'
                   '\tif armed {\n'
                   '\t\tsigErr = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)\n'
                   '\t\tarmed = false\n'
                   '\t}\n'
                   '\tmu.Unlock()\n')
        startline = '\tif err := cmd.Start(); err != nil {'
        waitline = '\n\twerr := cmd.Wait()\n'
        source = self.helper.read_text()
        self.assertEqual(source.count(cancel), 1)
        self.assertEqual(source.count(cleanup), 1)
        self.assertEqual(source.count(startline), 1)
        self.assertEqual(source.count(waitline), 1)
        module = self.root / 'fnliveneg'
        module.mkdir(parents=True)
        (module / 'go.mod').write_text('module example.test/fnliveneg\n\ngo 1.27\n')
        (module / 'shared.go').write_text(
            'package fnliveneg\n\nfunc Shadowed() bool { return true }\n')
        big = ['//go:build slow', '', f'// nonce {os.urandom(8).hex()}', 'package fnliveneg', '']
        big += [f'func F{i}() int {{ return {i} }}' for i in range(80000)]
        (module / 'big.go').write_text('\n'.join(big) + '\n')
        wrapper = self.root / 'wrapneg'
        wrapper.mkdir()
        real_go = shutil.which('go')
        pidfile = self.root / 'descneg.pid'
        sidecar = self.root / 't06n-sidecar.log'
        wrapper_go = wrapper / 'go'
        wrapper_go.write_text(
            '#!/bin/sh\n'
            '# Unconditional invocation marker: sidecar evidence of which\n'
            '# executable actually served each go call.\n'
            'if [ -n "$R2_T06_SIDECAR" ]; then\n'
            "  { echo \"wrapper pid=$$ ppid=$(ps -o ppid= -p $$ 2>/dev/null | tr -d ' ') argv=$*\"\n"
            '    echo "  R2_DESCENDANT_FILE=${R2_DESCENDANT_FILE:-<unset>}"; } >> "$R2_T06_SIDECAR"\n'
            'fi\n'
            'if [ -n "$R2_DESCENDANT_FILE" ]; then\n'
            '  sleep 600 >/dev/null 2>&1 </dev/null &\n'
            '  echo $! >> "$R2_DESCENDANT_FILE"\n'
            'fi\n'
            f'exec {real_go} "$@"\n')
        wrapper_go.chmod(0o755)
        env = self.go_env(
            PATH=f'{wrapper}{os.pathsep}{os.environ["PATH"]}',
            R2_T06_SIDECAR=str(sidecar), R2_T06_WRAPPER=str(wrapper_go),
            R2_T06_DESCENDANTS=str(pidfile))
        # Same test-only launch binding as the positive control: record the
        # resolved command, bind the nested listing to the wrapper before
        # Start, hand it the descendant contract, and record the completion
        # after the production single Wait. Real listing arguments stay
        # unchanged.
        bind = (
            '\t// test-only: record the resolved launch contract\n'
            '\tif sc := os.Getenv("R2_T06_SIDECAR"); sc != "" {\n'
            '\t\tif f, ferr := os.OpenFile(sc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); ferr == nil {\n'
            '\t\t\tfmt.Fprintf(f, "listing pid=%d ppid=%d resolved_cmd_path=%s cmd_args=%v\\n",\n'
            '\t\t\t\tos.Getpid(), os.Getppid(), cmd.Path, cmd.Args)\n'
            '\t\t\t_ = f.Close()\n'
            '\t\t}\n'
            '\t}\n'
            '\tcmd.Path = os.Getenv("R2_T06_WRAPPER")\n'
            '\tcmd.Env = append(os.Environ(), "R2_DESCENDANT_FILE="+os.Getenv("R2_T06_DESCENDANTS"))\n')
        waitlog = (
            '\tif sc := os.Getenv("R2_T06_SIDECAR"); sc != "" {\n'
            '\t\tif f, ferr := os.OpenFile(sc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); ferr == nil {\n'
            '\t\t\tfmt.Fprintf(f, "listing run_err=%v ctx_err=%v\\n", werr, ctx.Err())\n'
            '\t\t\t_ = f.Close()\n'
            '\t\t}\n'
            '\t}\n')
        # Disarm-only replacement for the final block: removes the group
        # signal while still reading and updating armed, so the negative
        # compiles and the sigErr declaration stays nil — a compile error
        # is not a behavioral negative.
        disarm_only = ('\tmu.Lock()\n'
                       '\tif armed {\n'
                       '\t\tarmed = false\n'
                       '\t}\n'
                       '\tmu.Unlock()\n')
        broken = self.deadline_copy('units-t06neg.go', budget_ms=2500, source=source,
                                    splices=[(cancel, cancel_leader_only),
                                             (cleanup, disarm_only),
                                             (startline, bind + startline),
                                             (waitline, waitline + waitlog)])
        request = json.dumps({'paths': ['shared.go', 'big.go'], 'modes': [['slow']]})
        leaks = set()
        try:
            # Prime the copy compile; that listing also expires under the
            # broken nets, so its leaked descendants are accounted for the
            # final reap below.
            self.guarded_helper(['go', 'run', str(broken)], module, env, request,
                                timeout=60)
            leaks.update(pidfile.read_text().split() if pidfile.exists() else [])
            pidfile.write_text('')
            sidecar.write_text('')
            run = self.guarded_helper(['go', 'run', str(broken)], module, env,
                                      request, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr[-400:])
            reported = pidfile.read_text().split()
            self.assertTrue(reported,
                            'wrapper never reported a live descendant')
            leaks.update(reported)
            side = sidecar.read_text() if sidecar.exists() else ''
            self.assertIn(f'R2_DESCENDANT_FILE={pidfile}', side,
                          'nested go list never received the wrapper contract')
            # Measured-run deadline evidence: the listing was alive at
            # expiry (killed through the context) — the survivor escaped
            # the kill; it did not merely outlive a finished listing.
            measured = [line for line in side.splitlines()
                        if 'listing run_err=' in line]
            self.assertTrue(measured, 'no measured-run sidecar evidence')
            self.assertTrue(
                any('run_err=signal: killed' in line
                    and 'ctx_err=context deadline exceeded' in line
                    for line in measured),
                measured)
            survivor = None
            for pid in reported:
                # kill(pid, 0) also succeeds for zombies: only a live
                # scheduler state proves the survivor really escaped.
                if self.proc_state(int(pid)) not in ('', 'Z'):
                    survivor = int(pid)
                    break
            self.assertIsNotNone(survivor,
                                 'negative control lost its surviving descendant')
        finally:
            for pid in leaks:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
            for name, path in (('t06n-sidecar.log', sidecar),
                               ('t06n-pidfile.txt', pidfile)):
                try:
                    shutil.copyfile(path, f'/tmp/opencode/{name}')
                except OSError:
                    pass

    def test_harness01_outer_guard_contains_nested_group_escapee(self):
        """Harness qualification: the launched leader closes its own
        pipes while staying alive, and its TERM-resistant descendant
        moves into its own process group and closes every inherited
        pipe — communicate() returns early with both alive, and a
        single-group kill reaches neither; the outer guard must still
        remove both from /proc — actual disappearance, never a mocked
        exit."""
        marker = self.root / 'escape.marker'
        escape = self.root / 'escape-child.py'
        escape.write_text(
            'import os, signal, time\n'
            'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
            'os.setpgid(0, 0)\n'
            'os.close(0)\n'
            'os.close(1)\n'
            'os.close(2)\n'
            'with open(os.environ["R2_ESCAPE_MARKER"], "w") as f:\n'
            '    f.write(f"{os.getpid()} {os.getpgid(0)}")\n'
            'time.sleep(300)\n')
        script = self.root / 'escape-leader.py'
        script.write_text(
            'import os, subprocess, sys, time\n'
            f'subprocess.Popen([sys.executable, {str(escape)!r}])\n'
            'os.close(0)\n'
            'os.close(1)\n'
            'os.close(2)\n'
            'time.sleep(300)\n')
        env = self.go_env(R2_ESCAPE_MARKER=str(marker))
        with self.assertRaises(subprocess.TimeoutExpired):
            self.guarded_helper([sys.executable, str(script)], self.root,
                                env, '', timeout=2)
        pid, pgid = (int(part) for part in marker.read_text().split())
        sid = self.last_sid
        self.assertNotEqual(pgid, sid,
                            'escapee stayed in the leader process group; '
                            'the fixture no longer escapes a single-group '
                            'kill')
        self.assertEqual(self.proc_state(pid), '',
                         'outer guard left the nested-group escapee alive')
        self.assertEqual(self.session_members(sid), [])

    def test_harness01_leader_only_drain_leaves_nested_escapee(self):
        """HARNESS-01 negative: the SAME bounded leader wait with a
        test-local drain that removes only the leader's own process
        group leaves the real TERM-resistant nested-group descendant
        observably alive in the session — only the full-session drain
        satisfies the cleanup invariant, and the crippled variant must
        fail it exactly there."""
        marker = self.root / 'escape-neg.marker'
        escape = self.root / 'escape-neg-child.py'
        escape.write_text(
            'import os, signal, time\n'
            'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
            'os.setpgid(0, 0)\n'
            'os.close(0)\n'
            'os.close(1)\n'
            'os.close(2)\n'
            'with open(os.environ["R2_ESCAPE_MARKER"], "w") as f:\n'
            '    f.write(f"{os.getpid()} {os.getpgid(0)}")\n'
            'time.sleep(300)\n')
        script = self.root / 'escape-neg-leader.py'
        script.write_text(
            'import subprocess, sys, time\n'
            f'subprocess.Popen([sys.executable, {str(escape)!r}])\n'
            'time.sleep(300)\n')
        env = self.go_env(R2_ESCAPE_MARKER=str(marker))
        real_drain = self.drain_session

        def leader_only_drain(sid, term_wait=3.0, kill_wait=5.0):
            # Test-local seam: TERM/KILL only the session leader's own
            # process group; other session-owned groups are never
            # examined, so a nested-group escapee survives it.
            try:
                with open(f'/proc/{sid}/stat') as stat:
                    fields = stat.read().rsplit(')', 1)[1].split()
            except (OSError, ValueError, IndexError):
                return
            if len(fields) <= 2 or fields[0] == 'Z':
                return
            try:
                os.killpg(int(fields[2]), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            deadline = time.monotonic() + term_wait
            while self.proc_state(sid) and time.monotonic() < deadline:
                time.sleep(0.1)
            if not self.proc_state(sid):
                return
            try:
                os.killpg(int(fields[2]), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            deadline = time.monotonic() + kill_wait
            while self.proc_state(sid) and time.monotonic() < deadline:
                time.sleep(0.1)

        sid = None
        self.drain_session = leader_only_drain
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.guarded_helper([sys.executable, str(script)], self.root,
                                    env, '', timeout=2)
            sid = self.last_sid
            pid, pgid = (int(part) for part in marker.read_text().split())
            self.assertNotEqual(pgid, sid,
                                'escapee stayed in the leader process group; '
                                'the fixture no longer escapes a single-group '
                                'kill')
            state = self.proc_state(pid)
            self.assertNotEqual(
                state, '',
                'leader-only drain removed the nested-group escapee; '
                'the seam no longer isolates the full-session behavior')
            self.assertNotEqual(state, 'Z',
                                'nested-group escapee is a zombie, not an '
                                'observable live survivor')
            self.assertIn(pid, self.session_members(sid),
                          'nested-group escapee is not in the guard session')
        finally:
            self.drain_session = real_drain
            if sid is not None:
                self.drain_session(sid)
        self.assertEqual(self.proc_state(pid), '',
                         'cleanup after the negative left the escapee alive')
        self.assertEqual(self.session_members(sid), [])

    def test_harness01_stalled_launcher_guard_drains_session(self):
        """HARNESS-GUARD-01 stalled-launcher control through the SAME
        guarded launcher the TIME controls use: a test-only helper
        starts a sleeper in its own nested process group, marks that the
        sleeper is live, then never answers its request. The guard must
        raise TimeoutExpired at the short test timeout, drain the entire
        owned session — go run, the stalled binary and the sleeper's
        nested group — and leave no live member. The original defective
        direct launcher had no containment at all and must never run
        again."""
        module = self.root / 'fnstall'
        module.mkdir(parents=True)
        (module / 'go.mod').write_text(
            'module example.test/fnstall\n\ngo 1.27\n')
        marker = self.root / 'stalled.marker'
        stall = self.root / 'stalled-launcher.go'
        stall.write_text(
            'package main\n\n'
            'import (\n\t"os"\n\t"os/exec"\n\t"syscall"\n\t"time"\n)\n\n'
            'func main() {\n'
            '\tsleeper := exec.Command("sleep", "300")\n'
            '\tsleeper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}\n'
            '\tif err := sleeper.Start(); err != nil {\n'
            '\t\tos.Exit(1)\n\t}\n'
            '\tif err := os.WriteFile(os.Getenv("R2_STALL_MARKER"),\n'
            '\t\t[]byte("sleeper live"), 0o644); err != nil {\n'
            '\t\tos.Exit(1)\n\t}\n'
            '\t// test-only stalled launcher: never answers its request.\n'
            '\ttime.Sleep(time.Hour)\n'
            '}\n')
        env = self.go_env(R2_STALL_MARKER=str(marker))
        request = json.dumps({'stalled': True})
        # Prime the compile cache through the guard so the stalled
        # binary provably starts — and writes its marker — inside the
        # short guard window instead of racing a cold compile.
        build = self.guarded_helper(
            ['go', 'build', '-o', str(self.root / 'stalled-launcher-bin'),
             str(stall)], module, self.go_env(), '', timeout=300)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        sid = None
        try:
            self.guarded_go_run(module, env, stall, request, timeout=2)
            self.fail('stalled launcher unexpectedly completed')
        except subprocess.TimeoutExpired:
            sid = self.last_sid
        self.assertIsNotNone(sid)
        # The sleeper provably reached its nested group before the
        # timeout fired; without the marker this control proves nothing.
        self.assertEqual(marker.read_text(), 'sleeper live')
        # The guard drained the whole owned session before surfacing the
        # timeout: go run, the stalled binary and the sleeper's own
        # group are gone from /proc — zombies are already-terminated.
        live = [pid for pid in self.session_members(sid)
                if self.proc_state(pid) not in ('', 'Z')]
        self.assertEqual(live, [], f'live members after guard drain: {live}')
        self.assertEqual(self.session_members(sid), [],
                         'session members (including zombies) after drain')

    # --- budget-shared controls (BUDGET-SHARED-01) ----------------------

    BUDGET_DEP = 'example.test/fntime2/dep'
    # Provenance id of the budget review base only: the original blobs
    # are embedded (FROZEN_BLOBS), so this never resolves through git.
    BUDGET_BASE = '76528f817b23c2ffe58032d4b397cbe31020f0d2'

    def budget_log_splice(self):
        """Test-only splice: the helper records the analysis budget it
        actually derived — the helper-side half of the handoff
        evidence."""
        return ('\tctx, cancel := context.WithTimeout('
                'context.Background(), budget)',
                '\tif budgetPath := os.Getenv("BUDGET_HELPER_LOG"); '
                'budgetPath != "" {\n'
                '\t\tif writeErr := os.WriteFile(budgetPath, '
                '[]byte(strconv.FormatInt(budget.Nanoseconds(), 10)), '
                '0o600); writeErr != nil {\n'
                '\t\t\treturn writeErr\n\t\t}\n\t}\n'
                '\tctx, cancel := context.WithTimeout('
                'context.Background(), budget)')

    def budget_go_wrapper(self, handoff_log):
        """PATH-first go wrapper recording pid, command and the actually
        forwarded unit budget of every intercepted go invocation."""
        real_go = shutil.which('go')
        self.assertIsNotNone(real_go, 'go toolchain not on PATH')
        wrapper = self.root / 'budget-go-wrapper'
        wrapper.mkdir()
        script = wrapper / 'go'
        script.write_text(
            '#!/bin/sh\n'
            '# test-only: record pid, command, forwarded unit budget\n'
            'printf "%s %s %s\\n" "$$" "$1" '
            '"${YABANIN_UNIT_REMAINING_NS-unset}" '
            '>> "$BUDGET_HANDOFF_LOG"\n'
            f'exec {real_go} "$@"\n')
        script.chmod(0o755)
        saved = {key: os.environ.get(key) for key in
                 ('BUDGET_HANDOFF_LOG', 'BUDGET_HELPER_LOG', 'PATH')}

        def restore():
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.addCleanup(restore)
        os.environ['BUDGET_HANDOFF_LOG'] = str(handoff_log)
        os.environ['PATH'] = str(wrapper) + os.pathsep + os.environ['PATH']

    def budget_invocations(self, handoff_log):
        """(pid, command, forwarded) per intercepted go invocation; the
        forwarded field keeps its raw string so 'unset' stays evidence."""
        if not handoff_log.exists():
            return []
        return [tuple(line.split()) for line in
                handoff_log.read_text().splitlines() if line.strip()]

    def budget_forwarded_runs(self, handoff_log):
        return [entry[2] for entry in self.budget_invocations(handoff_log)
                if entry[1] == 'run']

    def budget_short(self, module, seconds):
        """Test-only short shared budget via the module-default
        UNIT_VERIFY_SECONDS seam (a config without the versioned budget
        block); the approved pinned budgets are never shortened."""
        saved = module.UNIT_VERIFY_SECONDS
        module.UNIT_VERIFY_SECONDS = seconds
        self.addCleanup(setattr, module, 'UNIT_VERIFY_SECONDS', saved)
        self.addCleanup(module.reset_selection)
        module.reset_selection()

    def budget_load_variant(self, name, source, splices=()):
        """An edited copy of the caller loaded as its own module: unique
        name with an explicit spec and sys.modules binding, because the
        production module is already imported."""
        for old, new_text in splices:
            self.assertEqual(source.count(old), 1,
                             f'splice anchor not unique: {old!r}')
            source = source.replace(old, new_text)
        path = self.root / f'budget-{name}.py'
        path.write_text(source)
        spec = importlib.util.spec_from_file_location(
            f'r2_budget_{name}', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(module)
        return module

    def budget_original_caller(self):
        """The frozen review-base caller, loaded with an explicit spec
        and sys.modules binding; its sibling imports resolve through
        sys.modules exactly as in the accepted independent evidence."""
        blob = frozen_blob('budget_conservative')
        module = self.budget_load_variant('original_caller', blob)
        return module, hashlib.sha256(blob.encode()).hexdigest()

    def budget_original_policy_pair(self):
        """Bind the frozen review-base policy pair through the canonical
        sys.modules names — current modules are already imported, so the
        original critical_scope must be exec'd against the original
        conservative caller and both canonical bindings restored after.
        The original targets path creates no early deadline and has no
        unit bank."""
        target = self.root / 'budget-original-policy'
        shutil.copytree(Path(critical_conservative.__file__).parent, target,
                        ignore=shutil.ignore_patterns('__pycache__'))
        for name, key in (('critical_conservative.py',
                           'budget_conservative'),
                          ('critical_scope.py', 'budget_scope')):
            (target / name).write_text(frozen_blob(key))
        saved = {name: sys.modules[name] for name in
                 ('critical_conservative', 'critical_scope')}
        modules = {}
        for name in ('critical_conservative', 'critical_scope'):
            spec = importlib.util.spec_from_file_location(
                name, target / (name + '.py'))
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            modules[name] = module

        def restore():
            sys.modules.update(saved)
        self.addCleanup(restore)
        return modules, restore

    def budget_evidence(self, record):
        """Retain the record under R2_BUDGET_EVIDENCE_DIR with the exact
        parent/helper/base hashes its claims are bound to."""
        directory = os.environ.get('R2_BUDGET_EVIDENCE_DIR')
        if directory is None:
            return
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        lines = [
            f'parent-sha256={hashlib.sha256(Path(critical_conservative.__file__).read_bytes()).hexdigest()}',
            f'helper-sha256={hashlib.sha256(self.helper.read_bytes()).hexdigest()}',
            f'review-base={self.BUDGET_BASE}'] + list(record)
        (directory / (self.id().rsplit('.', 1)[-1] + '.txt')).write_text(
            '\n'.join(lines) + '\n')

    def test_budget01_missing_package_fails_closed(self):
        """A unit_rows call without the package would draw from an
        unknown shared budget: refused before any effect (API misuse)."""
        handoff_log = self.root / 'budget-missing-package.log'
        self.budget_go_wrapper(handoff_log)
        with self.assertRaises(ValueError) as caught:
            critical_conservative.unit_rows(self.root, ['shared.go'],
                                            self.helper, ['m1'])
        self.assertIn('requires the package', str(caught.exception))
        self.assertEqual(self.budget_invocations(handoff_log), [])

    def test_budget01_helper_handoff_edge_controls(self):
        """Helper-side handoff edges on a real FIFO-blocked gc importer:
        a valid forwarded budget yields complete required floor rows with
        the helper deriving exactly that budget; a nonpositive budget
        floors before any importer work (zero go list invocations is the
        authoritative assertion, captured before the FIFO cleanup's
        unblocking read end can complete a connection); a malformed
        value is refused; without the env the helper analyzes under its
        own compile-time default and resolves narrowly."""
        module = self.fifo_fixture()
        fifo = self.root / 'budget-edge.fifo'
        os.mkfifo(fifo)
        helper = self.deadline_copy(
            'budget-edge-units.go', budget_ms=8000,
            fifo=(self.BUDGET_DEP, str(fifo)),
            splices=[self.budget_log_splice()])
        paths = ['shared.go', 'm1only.go', 'blocked.go', 'm3only.go']
        request = json.dumps({'paths': paths,
                              'modes': [['m1'], ['m2'], ['m3']]})
        handoff_log = self.root / 'budget-edge.log'
        self.budget_go_wrapper(handoff_log)
        record = []

        def blocked_call(budget_log, forwarded):
            state, release, thread = self.fifo_writer(fifo)
            state['path'] = str(fifo)
            started = time.monotonic()
            try:
                run = self.guarded_helper(
                    ['go', 'run', str(helper)], module,
                    self.go_env(YABANIN_UNIT_REMAINING_NS=forwarded,
                                BUDGET_HELPER_LOG=str(budget_log)),
                    request, timeout=30)
                connected = state['connected']
            finally:
                self.stop_fifo_writer(state, release, thread)
            offset = None if connected is None else connected - started
            return run, connected, time.monotonic() - started, offset

        budget_log = self.root / 'budget-edge-5s-ns'
        run, connected, elapsed, offset = blocked_call(
            budget_log, str(5_000_000_000))
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        rows = {row['path']: row for row in json.loads(run.stdout)}
        self.assert_deadline_floor(rows, paths)
        self.assertIsNotNone(connected, 'real gc importer never opened')
        self.assertGreater(elapsed, 4.5)
        self.assertLess(elapsed, 7.5)
        self.assertEqual(int(budget_log.read_text()), 5_000_000_000)
        record.append(f'forwarded-5s: elapsed={elapsed:.3f}s '
                      f'connect-after-start={offset:.3f}s')

        handoff_log.unlink(missing_ok=True)
        budget_log = self.root / 'budget-edge-zero-ns'
        run, connected, elapsed, _ = blocked_call(budget_log, '0')
        self.assertEqual(run.returncode, 0, run.stderr[-400:])
        rows = {row['path']: row for row in json.loads(run.stdout)}
        self.assert_deadline_floor(rows, paths)
        self.assertIsNone(connected,
                          'importer work ran under a nonpositive budget')
        self.assertEqual([entry for entry in
                          self.budget_invocations(handoff_log)
                          if entry[1] == 'list'], [])
        self.assertEqual(int(budget_log.read_text()), 0)
        self.assertLess(elapsed, 1.8, 'zero budget spent unbounded time')
        record.append(f'forwarded-0: elapsed={elapsed:.3f}s '
                      'list-invocations=0')

        handoff_log.unlink(missing_ok=True)
        run = self.guarded_helper(
            ['go', 'run', str(helper)], module,
            self.go_env(YABANIN_UNIT_REMAINING_NS='not-a-number'), request,
            timeout=30)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('invalid YABANIN_UNIT_REMAINING_NS', run.stderr)
        invocations = self.budget_invocations(handoff_log)
        self.assertEqual([entry for entry in invocations
                          if entry[1] == 'list'], [])
        self.assertEqual([entry[2] for entry in invocations
                          if entry[1] == 'run'], ['not-a-number'])
        record.append(f'malformed: rc={run.returncode}')

        rows = self.run_units(module, ['shared.go', 'm1only.go'],
                              [['m1']], helper=helper)
        self.assertFalse(rows['shared.go'].get('resolution'),
                         rows['shared.go'])
        self.assertNotIn('Dispatch',
                         self.unit(rows['shared.go'], 'Shadowed')
                         .get('refs') or [])
        record.append('no-env-default: narrow')
        self.budget_evidence(record)

    def test_budget01_small_remainder_fails_closed(self):
        """A remainder inside the closure reserve forwards the 1ns floor
        and either floors immediately inside the remaining budget or
        fails closed at the parent deadline — never a widening back to
        the no-env default; an already-expired shared budget is refused
        before any go invocation at all."""
        cc = critical_conservative
        module = self.fifo_fixture()
        paths = ['shared.go', 'm1only.go', 'blocked.go', 'm3only.go']
        modes = ['m1', 'm2', 'm3']
        handoff_log = self.root / 'budget-small.log'
        self.budget_go_wrapper(handoff_log)
        record = []

        self.budget_short(cc, 0.2)
        cc.shared_deadline('fntime2', 0.2)
        handoff_log.unlink(missing_ok=True)
        started = time.monotonic()
        try:
            rows = cc.unit_rows(module, paths, self.helper, modes,
                                package='fntime2', config={})
        except ValueError as exc:
            rows = None
            self.assertIn('unit budget exhausted', str(exc))
        elapsed = time.monotonic() - started
        forwarded = self.budget_forwarded_runs(handoff_log)
        self.assertEqual(forwarded, ['1'], forwarded)
        # Neither bounded outcome may buy importer work: the 1ns budget
        # floors before any go list invocation, so a nonempty list here
        # would mean a reset/default importer run.
        self.assertEqual([entry for entry in
                          self.budget_invocations(handoff_log)
                          if entry[1] == 'list'], [],
                         'small remainder bought importer work')
        self.assertLess(elapsed, 4.0, 'small remainder was not bounded')
        if rows is None:
            record.append(f'small-remainder: forwarded=1ns failed-closed '
                          f'elapsed={elapsed:.3f}s')
        else:
            # A warm build cache can let the 1ns-budget helper floor and
            # return inside the small remainder: the contract is floor
            # or fail closed, never a reset to the 90s default, and the
            # asserted forwarded=1ns caps what the helper could spend.
            table = {row['path']: row for row in rows}
            self.assert_deadline_floor(table, paths)
            record.append(f'small-remainder: forwarded=1ns '
                          f'immediate-floor elapsed={elapsed:.3f}s')

        cc.reset_selection()
        cc.DEADLINES[('fntime2', 'unit')] = time.monotonic() - 1.0
        handoff_log.unlink(missing_ok=True)
        with self.assertRaises(ValueError):
            cc.unit_rows(module, paths, self.helper, modes,
                         package='fntime2', config={})
        self.assertEqual(self.budget_invocations(handoff_log), [])
        record.append('expired-seed: refused without any invocation')
        self.budget_evidence(record)

    def test_budget01_handoff_reserve_discriminates(self):
        """The closure reserve is load-bearing: the shipped caller
        forwards remaining-minus-reserve and its current call floors
        inside the parent deadline with complete rows, while an edited
        caller forwarding the raw remainder (reserve 0) has its helper
        deadline land past the parent's own absolute deadline and fails
        closed instead. Same fixture and one identical helper copy for
        both legs; each leg is bounded by its parent deadline itself."""
        cc = critical_conservative
        mutant = self.budget_load_variant(
            'reserve_zero', Path(cc.__file__).read_text(),
            [('UNIT_HANDOFF_RESERVE_NS = 500_000_000',
              'UNIT_HANDOFF_RESERVE_NS = 0')])
        module = self.fifo_fixture()
        fifo = self.root / 'budget-reserve.fifo'
        os.mkfifo(fifo)
        helper = self.deadline_copy(
            'budget-reserve-units.go', budget_ms=8000,
            fifo=(self.BUDGET_DEP, str(fifo)),
            splices=[self.budget_log_splice()])
        paths = ['shared.go', 'm1only.go', 'blocked.go', 'm3only.go']
        modes = ['m1', 'm2', 'm3']
        handoff_log = self.root / 'budget-reserve.log'
        self.budget_go_wrapper(handoff_log)
        record = []

        def current_call(caller, budget_log):
            handoff_log.unlink(missing_ok=True)
            os.environ['BUDGET_HELPER_LOG'] = str(budget_log)
            self.budget_short(caller, 2.5)
            caller.shared_deadline('fntime2', 2.5)
            state, release, thread = self.fifo_writer(fifo)
            state['path'] = str(fifo)
            started = time.monotonic()
            error = None
            try:
                try:
                    rows = caller.unit_rows(module, paths, helper, modes,
                                            package='fntime2', config={})
                except ValueError as exc:
                    rows, error = None, str(exc)
                connected = state['connected']
            finally:
                self.stop_fifo_writer(state, release, thread)
            return rows, error, connected, time.monotonic() - started

        shipped_log = self.root / 'budget-reserve-shipped-ns'
        rows, error, connected, elapsed = current_call(cc, shipped_log)
        self.assertIsNone(error, error)
        self.assert_deadline_floor({row['path']: row for row in rows},
                                   paths)
        self.assertIsNotNone(connected, 'real gc importer never opened')
        forwarded = int(self.budget_forwarded_runs(handoff_log)[0])
        self.assertTrue(1_900_000_000 < forwarded < 2_100_000_000,
                        forwarded)
        self.assertLessEqual(int(shipped_log.read_text()), forwarded)
        record.append(f'shipped: forwarded={forwarded}ns '
                      f'elapsed={elapsed:.3f}s')

        mutant_log = self.root / 'budget-reserve-zero-ns'
        rows, error, connected, elapsed = current_call(mutant,
                                                       mutant_log)
        self.assertIsNotNone(error, 'reserve-zero caller unexpectedly '
                            'accepted rows past the parent deadline')
        self.assertIn('unit budget exhausted', error)
        forwarded = int(self.budget_forwarded_runs(handoff_log)[0])
        self.assertTrue(2_400_000_000 < forwarded < 2_600_000_000,
                        forwarded)
        self.assertLess(elapsed, 6.0, 'reserve-zero leg was not bounded')
        record.append(f'reserve-zero: forwarded={forwarded}ns '
                      f'elapsed={elapsed:.3f}s')
        self.budget_evidence(record)

    def test_budget01_shared_fifo_qualification(self):
        """BUDGET-SHARED-01 REAL-FIFO qualification, the product form of
        the independently accepted reproducer: ONE absolute shared
        per-package unit budget across the baseline and current scans of
        a package whose gc importer is blocked on withheld export bytes.
        Fixed: the current call self-floors on the handed-off remainder
        inside the original 12s budget. Original (frozen review-base
        caller, no handoff) and reset (fresh deadline per invocation)
        both accept a full floor only after the original shared deadline
        — the test's own observed overrun is the independent oracle —
        while every leg stays bounded by the helper's own 8s analysis
        cap, so no leg ever needs forced cleanup."""
        cc = critical_conservative
        original_module, original_sha = self.budget_original_caller()
        module = self.fifo_fixture()
        fifo = self.root / 'budget-qual.fifo'
        os.mkfifo(fifo)
        log_splice = self.budget_log_splice()
        baseline_helper = self.deadline_copy(
            'budget-qual-baseline.go', budget_ms=8000,
            splices=[('\tfiles, table, err := parse(paths)\n',
                      '\ttime.Sleep(6 * time.Second)\n'
                      '\tfiles, table, err := parse(paths)\n'),
                     log_splice])
        current_helper = self.deadline_copy(
            'budget-qual-current.go', budget_ms=8000,
            fifo=(self.BUDGET_DEP, str(fifo)), splices=[log_splice])
        helper_shas = ','.join(
            copy.name + '='
            + hashlib.sha256(copy.read_bytes()).hexdigest()[:12]
            for copy in (baseline_helper, current_helper))
        paths = ['shared.go', 'm1only.go', 'blocked.go', 'm3only.go']
        modes = ['m1', 'm2', 'm3']
        handoff_log = self.root / 'budget-qual.log'
        self.budget_go_wrapper(handoff_log)
        record = [f'helpers={helper_shas}',
                  f'original-parent-sha256={original_sha}']

        def leg(name, caller, use_package, fresh_deadline=False):
            handoff_log.unlink(missing_ok=True)
            caller.DEADLINES.clear()
            remainders = getattr(caller, 'UNIT_REMAINDERS', None)
            if remainders is not None:
                remainders.clear()
            saved_verify = caller.UNIT_VERIFY_SECONDS
            caller.UNIT_VERIFY_SECONDS = 12
            real_shared = caller.shared_deadline
            if fresh_deadline:
                caller.shared_deadline = (
                    lambda package, seconds: time.monotonic() + seconds)
            try:
                # The one absolute 12s budget both scans draw from —
                # seeded after any fresh-deadline replacement and before
                # the baseline, so the fixed leg hands a real remainder
                # to the current call; the original caller ignores it
                # and the reset replacement re-dates every invocation.
                caller.shared_deadline('fntime2', 12)

                def rows_call(helper, row_paths, row_modes):
                    if use_package:
                        return caller.unit_rows(module, row_paths, helper,
                                                row_modes, package='fntime2',
                                                config={})
                    return caller.unit_rows(module, row_paths, helper,
                                            row_modes)

                baseline_log = self.root / f'budget-qual-{name}-baseline-ns'
                os.environ['BUDGET_HELPER_LOG'] = str(baseline_log)
                started = time.monotonic()
                baseline = rows_call(baseline_helper,
                                     ['shared.go', 'm1only.go'], ['m1'])
                baseline_rows = {row['path']: row for row in baseline}
                self.assertFalse(
                    baseline_rows['shared.go'].get('resolution'),
                    baseline_rows['shared.go'])
                self.assertNotIn(
                    'Dispatch',
                    self.unit(baseline_rows['shared.go'], 'Shadowed')
                    .get('refs') or [])

                current_log = self.root / f'budget-qual-{name}-current-ns'
                os.environ['BUDGET_HELPER_LOG'] = str(current_log)
                state, release, thread = self.fifo_writer(fifo)
                state['path'] = str(fifo)
                current_started = time.monotonic()
                try:
                    error = None
                    try:
                        current = rows_call(current_helper, paths, modes)
                    except ValueError as exc:
                        current, error = None, str(exc)
                    finished = time.monotonic()
                    # Connection and withheld-FIFO evidence is captured
                    # before the cleanup's unblocking read end can
                    # alter either fact.
                    connected = state['connected']
                    withheld = state['fd'] is not None
                    self.assertIsNotNone(
                        connected,
                        'real gc importer never opened the FIFO')
                    self.assertIsNone(error, f'{name}: {error}')
                    rows = {row['path']: row for row in current}
                    self.assert_deadline_floor(rows, paths)
                    self.assertIn(
                        'Dispatch',
                        self.unit(rows['m3only.go'], 'Third')
                        .get('refs') or [])
                    second = self.unit(rows['blocked.go'], 'Second')
                    self.assertFalse(second.get('refs'), second)
                    self.assertIn('Open', second.get('selrefs') or [])
                finally:
                    self.stop_fifo_writer(state, release, thread)
                entry = {'leg': name,
                         'total_s': round(finished - started, 3),
                         'current_s': round(finished - current_started, 3),
                         'forwarded': self.budget_forwarded_runs(
                             handoff_log),
                         'baseline_helper_ns': int(
                             baseline_log.read_text()),
                         'current_helper_ns': int(
                             current_log.read_text()),
                         'connect_after_current_s': round(
                             connected - current_started, 3),
                         'fifo_still_withheld': withheld}
                self.assertEqual(entry['baseline_helper_ns'],
                                 8_000_000_000, entry)
                record.append(json.dumps(entry, sort_keys=True))
                return entry
            finally:
                caller.shared_deadline = real_shared
                caller.UNIT_VERIFY_SECONDS = saved_verify
                caller.DEADLINES.clear()
                if remainders is not None:
                    remainders.clear()

        fixed = leg('fixed', cc, use_package=True)
        original = leg('original', original_module, use_package=False)
        reset = leg('reset', cc, use_package=True, fresh_deadline=True)

        # Fixed: both scans inside one absolute 12s budget; the current
        # call floored on a strictly smaller handed-off remainder.
        self.assertLessEqual(fixed['total_s'], 12.5, fixed)
        first, second_ns = (int(value) for value in fixed['forwarded'])
        self.assertTrue(0 < second_ns < first <= 12_000_000_000, fixed)
        self.assertLessEqual(fixed['current_helper_ns'], second_ns, fixed)
        self.assertTrue(fixed['fifo_still_withheld'], fixed)

        # Original: no handoff at all; the full floor was accepted only
        # after the original shared deadline, bounded by the helper cap.
        self.assertGreater(original['total_s'], 12.0, original)
        self.assertEqual(original['forwarded'], ['unset', 'unset'],
                         original)
        self.assertEqual(original['current_helper_ns'], 8_000_000_000,
                         original)

        # Reset: a fresh per-invocation deadline still cannot beat the
        # helper's own cap; the floor again lands past the original
        # budget with a full fresh handoff.
        self.assertGreater(reset['total_s'], 12.0, reset)
        self.assertGreater(int(reset['forwarded'][1]), 11_000_000_000,
                           reset)
        self.assertEqual(reset['current_helper_ns'], 8_000_000_000, reset)
        self.budget_evidence(record)

    def test_budget01_two_package_targets_bank_controls(self):
        """Real two-package targets() bank control, the product form of
        the accepted independent evidence: only production bodies change
        in a real git fixture and the actual conservative gate runs.
        Fixed: both packages selected, no live unit deadline after
        return, both remainders banked, and resuming one package leaves
        the other's banked remainder untouched. Isolated negative
        (current source with package-boundary pause_unit_budget disabled):
        correct selection, but pkg/other's 60s budget loses the controlled
        10s spent scanning pkg/auth. Original (frozen base policy pair,
        canonically bound): selection stays correct with no deadline or
        bank."""
        cc = critical_conservative
        self.addCleanup(cc.reset_selection)
        record = []
        config = {'critical_paths': ['pkg/**'], 'build_tags': ['']}

        root = self.root / 'budget-bank-repo'
        root.mkdir()
        for package, name in (('auth', 'Allowed'), ('other', 'Other')):
            directory = root / 'pkg' / package
            directory.mkdir(parents=True)
            (directory / (package + '.go')).write_text(
                'package ' + package + '\n\nfunc ' + name
                + '(n int) bool { return n > 0 }\n')
        (root / 'go.mod').write_text('module example.test/bank\n\n'
                                     'go 1.27.4\n')
        for args in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture',
                      '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'base']):
            subprocess.run(['git', *args], cwd=root, check=True,
                           capture_output=True)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                       cwd=root, text=True).strip()
        for package in ('auth', 'other'):
            path = root / 'pkg' / package / (package + '.go')
            path.write_text(path.read_text().replace('n > 0', 'n >= 0'))
        expected_selection = {'pkg/auth': ['Allowed'],
                              'pkg/other': ['Other']}
        expected_keys = {('pkg/auth', 'unit'), ('pkg/other', 'unit')}

        def run_targets(scope, caller):
            cc.reset_selection()
            caller.DEADLINES.clear()
            remainders = getattr(caller, 'UNIT_REMAINDERS', None)
            if remainders is not None:
                remainders.clear()
            selected = scope.targets(root, base, config)
            return {package: sorted(row['name'] for row in rows)
                    for package, rows in selected.items()}

        saved_verify = cc.UNIT_VERIFY_SECONDS
        cc.UNIT_VERIFY_SECONDS = 60
        try:
            # Fixed: real selection, then the full bank contract.
            names = run_targets(critical_scope, cc)
            self.assertEqual(names, expected_selection,
                             'selection/setup failed, not bank evidence')
            self.assertEqual(set(cc.UNIT_REMAINDERS), expected_keys,
                             sorted(cc.UNIT_REMAINDERS))
            self.assertFalse(
                cc.DEADLINES,
                f'unit deadlines live after targets: {sorted(cc.DEADLINES)}')
            auth_before = cc.UNIT_REMAINDERS[('pkg/auth', 'unit')]
            other_before = cc.UNIT_REMAINDERS[('pkg/other', 'unit')]
            for remainder in (auth_before, other_before):
                self.assertGreater(remainder, 0)
                self.assertLess(remainder, 60)
            other_deadline = cc.resume_unit_deadline('pkg/other', 60)
            self.assertNotIn(('pkg/auth', 'unit'), cc.DEADLINES,
                             'other package resumed auth deadline')
            self.assertEqual(cc.UNIT_REMAINDERS[('pkg/auth', 'unit')],
                             auth_before,
                             'other package changed auth remainder')
            self.assertLess(
                abs((other_deadline - time.monotonic()) - other_before),
                0.2, 'other package did not resume its own remainder')
            record.append(f'fixed: auth_banked={auth_before:.3f}s '
                          'other_resumed='
                          f'{other_deadline - time.monotonic():.3f}s')

            # Isolated negative: disable only package-boundary banking.
            # The fake clock makes pkg/auth's scan consume exactly 10s;
            # pkg/other must lose those seconds if its deadline remains
            # live while unrelated package work runs.
            real_pause = cc.pause_unit_budget
            real_changed = cc.changed_functions
            real_monotonic = cc.time.monotonic
            real_archive = critical_scope.source.archive
            clock = {'now': 1000.0}

            def changed_with_a_cost(_root, _baseline, package, _helper,
                                    _changes, _build_tags, _config):
                if package == 'pkg/auth':
                    clock['now'] += 10
                selection = cc.Selection(package)
                cc.RUNS[package] = (selection, None, None)
                return [{'file': package + '/' + package.split('/')[-1]
                         + '.go', 'name': expected_selection[package][0],
                         'hash': package, 'start': 1, 'end': 2,
                         'recv': ''}]

            cc.pause_unit_budget = lambda _package: None
            cc.time.monotonic = lambda: clock['now']
            cc.changed_functions = changed_with_a_cost
            critical_scope.source.archive = lambda *_args: None
            try:
                names = run_targets(critical_scope, cc)
            finally:
                cc.pause_unit_budget = real_pause
                cc.changed_functions = real_changed
                cc.time.monotonic = real_monotonic
                critical_scope.source.archive = real_archive
            self.assertEqual(names, expected_selection)
            self.assertEqual(set(cc.DEADLINES), expected_keys,
                             'isolated negative must leave both '
                             'deadlines live')
            self.assertFalse(
                cc.UNIT_REMAINDERS,
                'bank filled while package-boundary pause was disabled')
            other_remaining = (cc.DEADLINES[('pkg/other', 'unit')]
                               - clock['now'])
            self.assertEqual(
                other_remaining, 50,
                'pkg/other should lose pkg/auth\'s controlled 10s scan')
            record.append('removed: pkg/other remaining='
                          f'{other_remaining:.0f}s after pkg/auth spent 10s')
        finally:
            cc.UNIT_VERIFY_SECONDS = saved_verify
            cc.reset_selection()

        # Original: canonically bound base policy pair — its targets
        # path creates no early deadline and has no bank, while the
        # selection itself stays correct.
        modules, restore_pair = self.budget_original_policy_pair()
        original_cc = modules['critical_conservative']
        try:
            original_cc.UNIT_VERIFY_SECONDS = 60
            names = run_targets(modules['critical_scope'], original_cc)
            self.assertEqual(names, expected_selection,
                             'original selection must stay correct')
            self.assertFalse(
                original_cc.DEADLINES,
                f'original created unit deadlines: '
                f'{sorted(original_cc.DEADLINES)}')
            self.assertFalse(
                getattr(original_cc, 'UNIT_REMAINDERS', {}),
                'original unexpectedly banked unit remainders')
            record.append('original: no-deadlines bank-empty')
        finally:
            restore_pair()
            original_cc.DEADLINES.clear()
            remainders = getattr(original_cc, 'UNIT_REMAINDERS', None)
            if remainders is not None:
                remainders.clear()
        self.assertIs(sys.modules['critical_conservative'], cc,
                      'canonical conservative binding was not restored')
        self.assertIs(sys.modules['critical_scope'], critical_scope,
                      'canonical scope binding was not restored')
        self.budget_evidence(record)


if __name__ == '__main__':
    unittest.main()

import re
from flask import jsonify
from flask import session
from functools import wraps
import random
import pandas as pd
import string
def return_error(error="SOMETHING_WENT_WRONG", message="Error", data={}, code=200):
    return jsonify({"success": False, "error": error, "message": message, "data": data})


def return_success(data={}, status="SUCCESS", code=200):
    if isinstance(data, (dict, list)):
        if isinstance(data, (list)):
            l_data = {}
            l_data['status'] = status
            l_data['data'] = data
            return jsonify({"success": True, "data": l_data})
        if data.get('status', False):
            return jsonify({"success": True, "data": data})
        else:
            data['status'] = status
            return jsonify({"success": True, "data": data})
    else:
        raise Exception(f'data obj must be list or dict but got {type(data)}')


EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def to_nullable(value, cast=None):
    if pd.isna(value):
        return None
    if cast:
        return cast(value)
    return value

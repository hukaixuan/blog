from flask import Blueprint
from ..models import Permission

main = Blueprint('main', __name__)  # 第一个参数为蓝本名，第二个参数为 the module or package where the blueprint located

from . import views, errors


@main.app_context_processor
def inject_permissions():
	return dict(Permission=Permission)

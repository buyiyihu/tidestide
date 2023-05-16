"""Authorization elements.

  Resource stands for system resources
  Attribute stands for user attributes collection
  Rule stands for accessibily determinating logics

  A complete accessibily determinating operatioin chain:

    request ==>

    get user identity
    -> get user attributes data
    -> get all rules-resource mapping info
    -> calculate rule by the user's attribute one by one to collect all resources
        - resource = attribute x rule
        - resource = resource1 + resource2 + resource3 + ...
    -> convert resource value to bool or db filters

    if not accesible -> return "Unauthorized"
    or             -> execute the business and query code

    ==> response

Author: buyiihoo
"""


from itertools import chain
from typing import Any, Dict, List

from flask_jwt import current_identity
from sqlalchemy import func

from app import auth, db
from .constant import AuthResourcesType as RT
from app.models import (
    AuthAttributeFileds,
    AuthAttributes,
    AuthConstants,
    AuthResourceGroup,
    AuthResources,
    AuthRuleEntry,
    Users,
)
from app.utils.maths import calculate_position



class Attributes:

    """User attributes related actions, including modifying, adding,
    deleting."""

    @classmethod
    def add_an_attribute(
        cls, name: str, description: str, fields: List[Dict[str, str]]):
        dup = cls.check_fields_duplication(fields)
        if dup is not None:
            raise ValueError(f"Field '{dup}' duplicates")
        ordinal = (
            AuthAttributes.query.with_entities(func.max(AuthAttributes.ordinal))
            .filter_by(is_del=0)
            .with_for_update()
            .scalar()
        )
        dup = AuthAttributes.query.filter_by(name="name").first()
        if dup:
            db.session.commit()
            return ValueError(f"A attribute with name '{name}' already exists")
        attr = AuthAttributes.create(
            name=name, description=description, slots=len(fields), ordinal=ordinal + 1
        )
        total = (
            AuthAttributes.query.with_entities(func.sum(AuthAttributes.slots))
            .filter_by(is_del=0)
            .with_for_update()
            .scalar()
        )
        auth.ATTRIBUTE_SLOTS = total
        db.session.commit()
        cls.add_fields_for_new_attr(attr.id, fields)
        return 

    @classmethod
    def edit_an_attribute(
        cls, attr_id: int, name: str, description: str, fields: List[Dict[str, str]]):
        # TODO: a gloabal lock to hold authorizing

        dup = cls.check_fields_duplication(fields)
        if dup is not None:
            return Error.ENTITY_DUPLICATION(data=f"Field '{dup}' duplicates")
        attr = AuthAttributes.query.with_for_update().get(attr_id)
        if name != attr.name:
            dup = AuthAttributes.query.filter_by(name="name").with_for_update().first()
            if dup:
                db.session.commit()
                return Error.ENTITY_ALREADY_EXIST(
                    data=f"A attribute with name '{name}' already exists"
                )
            attr.name = name
        attr.description = description

        with auth.modification_permisson:
            if attr.slots != len(fields):
                attr.slots = len(fields)
                total = auth.slots
                auth.ATTRIBUTE_SLOTS = (
                    total  # TODO lock and publish
                )
            db.session.commit()
            cls.edit_fields(attr_id, fields)

        return Error.GOOD()

    @classmethod
    def add_fields_for_new_attr(cls, attr_id, fields: List[Dict[str, str]]) -> None:
        data = []
        _ = AuthAttributes.query.with_for_update().get(attr_id)
        for n, field in enumerate(fields):
            af = AuthAttributeFileds(
                attr_id=attr_id,
                name=field["name"],
                description=field["description"],
                value=1 << n,
            )
            data.append(af)
        db.session.add_all(data)
        db.session.commit()

    @classmethod
    def add_a_field_for_existing_attr(cls, args) -> AuthAttributeFileds:
        """A compatible method."""

        attr = AuthAttributes.retrieve({"id": 1})
        attr.slots += 1
        max_no = (
            AuthAttributeFileds.query.with_entities(
                func.max(AuthAttributeFileds.ordinal)
            )
            .filter_by(is_del=0)
            .scalar()
        )
        field = AuthAttributeFileds.create(
            name=args.name, ordinal=max_no + 1, value=1 << max_no
        )
        return field

    @classmethod
    def edit_fields(cls, attr_id, fields: List[Dict[str, str]]) -> None:
        constant = (
            AuthConstants.query.filter_by(name="attributes_version")
            .with_for_update()
            .one()
        )
        attr = AuthAttributes.query.with_for_update().get(attr_id)
        exists = AuthAttributeFileds.retrieve(criteria={"attr_id": attr_id})
        exists_dict = {af.id: af for af in exists}
        incoming, models, change = set(), [], []
        for n, field in enumerate(fields):
            # Note that the fields are not supposed to be reordered
            fid = field.get("id")
            if fid:
                item = exists_dict.get(fid)
                item.name = field["name"]
                item.description = field["description"]
                change.append(item.ordinal)
                item.ordinal = n + 1
                incoming.add(item.id)
            else:
                item = AuthAttributeFileds(
                    name=field["name"], description=field["description"], ordinal=n + 1
                )
                change.append(0)
                models.append(item)
        for fid in exists_dict.keys() - incoming:
            exists_dict[fid].is_del = 1
        db.session.add_all(models)
        if not cls.has_changed(change):
            db.session.commit()

        base = (
            AuthAttributes.query.with_entities(func.sum(AuthAttributes.slots))
            .filter(AuthAttributes.ordinal < attr.ordinal)
            .scalar()
        )
        users = Users.retrieve()

        for us in users:
            us.attributes = cls.change_attr_value(
                us.attributes, change, base, attr.slots
            )

        rules = AuthRuleEntry.retrieve()
        for rule in rules:
            if not rule.structure:
                rule.value = rule.value[:2] + cls.change_attr_value(
                    rule.value[2:], change, base, attr.slots
                )
            else:
                _rule = rule.value.split(".")
                new = []
                for rl in _rule:
                    if len(rl) == 2:
                        new.append(rl)
                        continue
                    new.append(
                        rl[:2] + cls.change_attr_value(rl[2:], change, base, attr.slots)
                    )
                rule.value = ".".join(new)
        attr.slots = len(change)
        constant.value = str(int(constant.value) + 1)
        db.session.commit()

    @classmethod
    def get_all_attibutes(cls):
        attrs = AuthAttributes.retrieve()
        attrs_map = {at.id: at for at in attrs}
        fields = AuthAttributeFileds.retrieve()
        field_to_resource_group = attrs_map
        rules = AuthRuleEntry.retrieve()
        for field in fields:
            for rule in rules:
                if field.value * rule:
                    field_to_resource_group[fields] = rule.value
            # for user in users:
            #     if user.attribute * field:
            #         field_to_resource_group_users.add(user)
        return field_to_resource_group

    @classmethod
    def has_changed(cls, change):
        for n, i in enumerate(change):
            if i != n + 1:
                return True
        else:
            return False

    @classmethod
    def change_attr_value(cls, value, change, base, length):
        bits = str(int(value, base=16))
        piece = bits[base : base + length]
        new_piece = ""
        for i in change:
            if i == 0:
                new_piece += "0"
            else:
                new_piece += piece[i - 1]
        return hex(int(bits[:base] + new_piece + bits[base + length :], base=2))[2:]

    @classmethod
    def check_fields_duplication(cls, fields: List[Dict[str, str]]):
        names = set()
        for field in fields:
            name = field["name"]
            if name in names:
                return name
            names.add(name)

    @classmethod
    def create_sum_value(cls, fields: List[List[int]]):
        value = 0
        field_info_map, base, _ = cls.get_value_map()
        for fid in chain.from_iterable(fields):
            at_ord, _, val = field_info_map[fid]
            value += val << base[at_ord]
        return hex(value)[2:]

    @classmethod
    def load_from_sum_value(cls, value: str):
        # TODO: multi upgrade
        res = []
        value = str(int(value, base=16))
        _, _, index_field_map = cls.get_value_map()
        for n, val in enumerate(value[::-1]):
            if val == "0":
                continue
            index_field_map[n]
            res.append(index_field_map[n])
        return res

    @classmethod
    # TODO: cache
    def get_value_map(cls):
        attrs = (
            AuthAttributes.query.with_entities(
                AuthAttributes.id, AuthAttributes.ordinal, AuthAttributes.slots
            )
            .order_by(AuthAttributes.ordinal)
            .with_for_update(read=True)
            .all()
        )
        base, ordinals_by_attr = [], {}

        _base = 0
        for at in attrs:
            base.append(_base)
            _base += at.slots
            ordinals_by_attr[at.id] = at.ordinal

        field_info_map, index_field_map = {}, {}
        fields = AuthAttributeFileds.retrieve(
            columns=["id", "attr_id", "name", "ordinal", "value"]
        )
        length = len(fields)
        field_counts_by_attr = {}
        if length != base[-1] + attrs[-1].slots:
            db.session.commit()
            raise RuntimeError("Total length of fields conflicts with slots")
        for fi in fields:
            if fi.value != 1 << (fi.ordinal - 1):
                db.session.commit()
                raise RuntimeError("Fields ordinal conflict with value")
            field_counts_by_attr[fi.attr_id] = (
                field_counts_by_attr.get(fi.attr_id, 0) + 1
            )
            field_info_map[fi.id] = ordinals_by_attr[fi.attr_id], fi.ordinal, fi.value
            index_field_map[base[ordinals_by_attr[at.id] - 1] + fi.ordinal - 1] = fi
        if not all(map(lambda at: field_counts_by_attr[at.id] == at.slots, attrs)):
            db.session.commit()
            raise RuntimeError("Fields counts conflict with slots")
        db.session.commit()
        return field_info_map, base, index_field_map


class ResourceService:
    """Service class to deal resources."""

    @classmethod
    def create_resources(cls, data: List[Dict]):
        # data: tree of json
        parent = AuthResources.query.filter_by(**Constant.ROOT_PRAM).one()
        structure = cls.traverse_data(data, parent)
        AuthConstants.query.filter_by(name="resource_structure").update(
            {"value": ".".join(structure)}, synchronize_session=False
        )
        const = AuthConstants.retrieve(criteria={"name": "resource_version"})
        const.value = str(int(const.value) + 1)
        const.save()

    @classmethod
    def traverse_data(cls, data: Dict, parent: AuthResources) -> List:
        """Traverser incoming data to create resource tree."""
        models = []
        bro = None
        maxm = 1
        for cnt, item in enumerate(data):
            name = item["name"]
            # if not name.isalnum():
            #     raise Error.INVALID_DATA_TYPE(data="name can only be alphanumeric")
            if bro is None:
                _, _bd, _dp, _max = parent.generate_derivation()
            else:
                _dp, _, _bd, _max = bro.generate_derivation()
            ar = AuthResources(
                name=item["name"],
                qualname=parent.qualname + "." + name,
                hreadname=item["human_name"],
                description=item.get("description", ""),
                value_dp=_dp,
                value_bd=_bd,
                type=10,
            )
            models.append(ar)
            bro = ar
            maxm = _max if _max > maxm else maxm
            children = item.get("children", None)
            if children:
                ch_models, _max, children_count = cls.traverse_data(children, parent=ar)
                models.extend(ch_models)
                maxm = _max if _max > maxm else maxm
            else:
                children_count = 0
            ar.children_count = children_count
        else:
            # Update the data of the last one when it's alone
            if not children:
                ar.generate_derivation()
        # if parent.ordinal == cls.ROOT:
        if parent.value_dp == "0,1" and parent.value_bd == "1,1":
            structure = [cnt + 1]
            for n, m in enumerate(models):
                m.value = maxm // m.value_[0] * m.value_[1]
                structure.append(m.children_count)
                m.ordinal = n + 2
            parent.value = maxm // parent.value_[0] * parent.value_[1]
            db.session.add_all(models)
            db.session.commit()
            return structure
        else:
            return models, maxm, cnt + 1

    @classmethod
    def create_group(
        cls,
        name,
        resource_ids: List[int],
        description="",
    ):
        # create a bitmap, start from low position
        resources = (
            AuthResources.query.with_entities(AuthResources.id, AuthResources.ordinal)
            .filter(AuthResources.id.in_(resource_ids))
            .order_by(AuthResources.ordinal)
            .all()
        )
        value = 0
        for re in resources:
            value += 1 << (re.ordinal - 1)
        AuthResourceGroup.create(
            name=name, description=description, value=hex(value)[2:]
        )
        return Error.GOOD()

    @classmethod
    def get_all_resources(cls, resource_ids=None) -> Dict:
        """Retrieve all the resources and ouptput a tree structured json."""
        data = {"subs": {0: {"node": "root", "subs": {}}}}
        if resource_ids is not None:
            if not resource_ids:
                return cls.convert_dict(data["subs"][0])
            resources = AuthResources.retrieve(
                crtr_list={"id": resource_ids},
            )
        else:
            resources = AuthResources.retrieve(criteria={"type": 10})
        for res in resources:
            struct = calculate_position(res.value_dp, res.value_bd)
            tmp = data
            for ord in struct:
                tmp = tmp["subs"].setdefault(
                    ord,
                    {
                        "subs": {},
                    },
                )
            else:
                tmp["node"] = res
        return cls.convert_dict(data["subs"][0])

    @classmethod
    def convert_dict(cls, data):
        res = data["node"]
        if res == "root":
            node = {
                "tag": "root",
                "name": "root",
            }
        else:
            node = {"id": res.id, "tag": res.name, "name": res.hreadname}

        subs = data["subs"]
        children = []
        ordinal = sorted(list(subs.keys()))
        for i in ordinal:
            child = cls.convert_dict(subs[i])
            children.append(child)
        if children:
            node["children"] = children
        return node

    @classmethod
    def get_resouces_list(cls, resource_ids):
        if resource_ids is None:
            resources = AuthResources.query.filter_by(
                type=AuthResources.Type.TEMPORARY.value, is_del=0
            ).all()
        else:
            resources = AuthResources.retrieve(crtr_list={"id": resource_ids})
        return [res.name for res in resources]


class Rule:

    # WARNING: for filters, not selected means all pass

    __slots__ = (
        "structure",
        "_structure",
        "value",
        "_value",
        "_len",
        "db_model",
        "resource",
    )

    OPERATOR_ABBR = {
        "==": "==",
        "!=": "!=",
        "in": "in",
        "notin": "ni",
        "and": "ad",
        "or": "or",
    }
    OPERATOR_FULL = {v: k for k, v in OPERATOR_ABBR.items()}

    def __init__(self, structure: str, value: str, model=None, resource=None):
        self.structure = structure
        self._structure = list(map(int, structure.split("."))) if structure else ""
        # TODO: in out dup cal
        self.value = value
        self._value = value.split(".") if structure else value
        self._len = len(self._value)
        self.db_model = model
        self.resource = None

    def __call__(self, model=None, resource=None):
        if model:
            self.db_model = model
        if resource:
            self.resource = resource

    def save(self, model, **cols):
        if self.db_model:
            self.db_model.structure = self.structure
            self.db_model.value = self.value
        else:
            self.db_model = model(structure=self.structure, value=self.value, **cols)
        self.db_model.save()

    def __mul__(self, other):

        # TODO: class assert
        if not self.structure:
            res = self._calculate(self.value, other.value)
        else:
            tmp = {}
            for n, (idx, rule) in enumerate(
                zip(self._structure[::-1], self._value[::-1])
            ):
                if tmp.get(self._len - n - 1) is None:
                    res = self._calculate(rule, other.value)
                else:
                    if rule == "ad":
                        res = all(tmp[self._len - n - 1])
                    elif rule == "or":
                        res = any(tmp[self._len - n - 1])
                    else:
                        raise ValueError(f"Got illegal compound operator:{rule}")
                if n == self._len - 1:
                    # Avoid duplication
                    break
                tmp.setdefault(idx, []).append(res)
        return self.resource if res else None

    __rmul__ = __mul__

    def _calculate(self, rule: str, attrs: str):
        opr, rule, attrs = rule[:2], int(rule[2:], base=16), int(attrs, base=16)
        if opr == "==":
            return rule & attrs
        elif opr == "!=":
            return not rule & attrs
        elif opr == "in":
            return rule & attrs
        elif opr == "ni":
            return not rule & attrs
        else:
            raise ValueError(f"Got illegal oprerator:{opr}")

    def to_json(self, value=None):
        """Load the rule data from str to a tree structured json."""
        if not self._structure or value:
            _value = value if value else self._value
            opr, value = _value[:2], _value[2:]
            attributes = Attributes.load_from_sum_value(value)
            rule = {
                "attr_id": attributes[0].attr_id,
                "operator": self.OPERATOR_FULL[opr],
                "value": attributes[0].id if "=" in opr else [v.id for v in attributes],
            }
            return rule
        else:
            tmp = {}
            for n, (idx, rule) in enumerate(
                zip(self._structure[::-1], self._value[::-1])
            ):
                if tmp.get(self._len - n - 1) is None:
                    _rule = self.to_json(value=rule)
                else:
                    _rule = {
                        "attr_id": 0,
                        "operator": self.OPERATOR_FULL[rule],
                        "subs": tmp[self._len - n - 1],
                    }
                if n == self._len - 1:
                    # Avoid data conflict
                    return _rule
                tmp.setdefault(idx, []).append(_rule)

    @classmethod
    def load_json(cls, json_data: Dict[str, Any]):
        """basic operator: ==, != , in, notin combining operator: and, or.

        Some demo data:

        {
            "attr_id": 2,
            "operator": "==",
            "value":23,
        },
        {
            "attr_id": 3,
            "operator": "in",
            "value":[23,24,25]
        }
        {
            "attr_id":0,
            "operator":"and",
            "subs":[
                {
                    "attr_id": 4,
                    "operator": "==",
                    "value":23,
                },
                {
                    "attr_id": 0,
                    "operator": "or",
                    "subs":[
                        {
                            "attr_id": 4,
                            "operator": "==",
                            "value":23,
                        },
                        {
                            "attr_id": 5,
                            "operator": "==",
                            "value":69,
                        }
                    ]
                }
            ]
        }
        """
        tree_idx, node_value = cls.fold_a_rule(json_data)
        if tree_idx is None:
            tree_idx, value = "", node_value
        else:
            tree_idx, value = ".".join(tree_idx), ".".join(node_value)

        return cls(tree_idx, value)

    @classmethod
    def fold_a_rule(cls, json_data: Dict):
        """Convert a tree structured data into a one-dimension str."""
        attr_id, value = json_data.get("attr_id"), json_data.get("value")
        opr, subs = json_data.get("operator"), json_data.get("subs")
        opr_flag = cls.OPERATOR_ABBR.get(opr)
        if opr_flag is None:
            raise ValueError(f"Invalid expression: {opr}")
        if attr_id == 0:
            tree_index, node_value = [0], [opr_flag]
            for sub in subs:
                tree_idx, node_val = cls.fold_a_rule(sub)
                if not tree_idx:
                    node_value.append(node_val)
                    tree_index.append(0)
                else:
                    offset = len(tree_index)
                    tree_index.extend(
                        [0 if n == 0 else ti + offset for n, ti in enumerate(tree_idx)]
                    )
                    node_value.extend(node_val)
            return tree_index, node_value
        else:
            if isinstance(value, int):
                value = [value]
            rule_value = opr_flag + Attributes.create_sum_value(value)
            return None, rule_value

    @classmethod
    def get_all(cls):
        # TODO: cache
        return auth.db_rules.retrieve()


class ResourceGroup:

    __slots__ = ("db_id", "value", "_value")

    def __init__(self, value=None, int_value=None, db_id=None):
        self.db_id = db_id
        self.value = value
        self._value = int(value, base=16) if value else int_value

    def __add__(self, other):
        if not other:
            return self
        if not isinstance(other, self.__class__):
            return NotImplemented
        res = self._value | other._value
        return self.__class__(int_value=res)

    def load_resource(self, base):
        """

        WARNING: Currently assume base point is a view func
        Node bit value and its meaning:
        +--------------------+----------------------+------------------------+
        |                    |         True         |          False         |
        +--------------------+----------------------+------------------------+
        |    view function   |      CAN access      |      CANNOT access     |
        |                    |                      |                        |
        +--------------------+----------------------+------------------------+
        |        DATA        |    All conditions,   | None or some conditions|
        |                    |    use NO filters    | use filters            |
        +--------------------+----------------------+------------------------+
        |      DATA_RUN      |    All conditions,   |  USE filters to judge  |
        |                    |    use NO filters    |                        |
        +--------------------+----------------------+------------------------+
        |     DATA_FILTERS   |    Accesible value,  |  Non-accesible value,  |
        |                    |    in `in_` list     |   NOT in the list      |
        +--------------------+----------------------+------------------------+


        """
        # TODO: cache
        if not base.ordinal & self._value:
            return False, None
        if not base.selects:
            return True, None
        result = {}
        for flt in base.selects:
            flag = flt.value & self._value
            if flt.type == RT.DATA:
                if flag:
                    continue
                result[flt.column] = _res = []
                for select in flt.selects:
                    # select.value is a tuple of name and value
                    if select.value[1] & self._value:
                        _res.append(select.value)
            elif flt.type == RT.DATA_RUN:
                if not flag:
                    result.setdefault(flt.column, []).append(
                        flt.selects(current_identity)
                    )
            else:
                raise RuntimeError("Got a illegal fliter type")
        return True, result


class Entity:
    """Back-end entities' structure.

            view function
            /  \
           /    \
         DATA   DATA_RUN
           |
           |
    DATA_FILTERS...
    """

    __slots__ = (
        "name",
        "qual_name",
        "type",
        "column",
        "selects",
        "db_model",
        "parent",
        "value_dp_e",
        "value_bd_e",
    )

    def __init__(self, name, type=RT.API.value, column=None, selects=None, parent=None):
        self.name = name
        self.qual_name = name
        self.type = type
        self.column = column
        self.selects = selects
        self.db_model = None
        self.parent = parent

    def __hash__(self):
        return hash(self.qual_name)

    def __eq__(self, other):
        return self.__class__ is other.__class__ and self.qual_name == other.qual_name

    def link(self, model):
        self.db_model = model
        if self.db_model.value_dp:
            self.evaluate()
        else:
            self.value_dp_e = self.value_bd_e = None

    def __getattr__(self, attr):
        return getattr(self.db_model, attr)

    def evaluate(self):
        self.value_dp_e = tuple(map(int, self.db_model.value_dp.split(",")))
        self.value_bd_e = tuple(map(int, self.db_model.value_bd.split(",")))


class Filters:
    """For data filters at endpoint, could upgrade to support `not` conditions
    when needed.

    This class is used for view functions' data filters including initializing registering, and connnecting.
    Pass initialized filters to the decorator of view functions:

    @auth_check(
        filters = Filters(...)
    )
    def view_func():
        pass
    """

    __slots__ = ("_all", "_filters")

    def __init__(self, *filters):
        if not filters:
            raise RuntimeError("Empty filters")
        _all = []
        _filters = []
        for name, attr, values in filters:
            is_container = hasattr(values, "__iter__")
            if is_container and len(values) > 7:
                # It is not proper to have too many options
                raise RuntimeError(
                    "Too much value selections, keep it under 7 or add a new column"
                )
            # There are 2 kind of options for now, a list of values and a runtime calculated value.
            if is_container:
                flt = Entity(name, type=RT.DATA.value, column=attr)
                _all.append(flt)
                _selects = []
                # Each option (i.e. item for selecting) should also be a entity.
                for name, value in values:
                    select = Entity(
                        name, type=RT.DATA_FILTER.value, parent=flt, selects=value
                    )
                    _selects.append(select)
                flt.selects = _selects
                _all.extend(_selects)
                _filters.append(flt)
            else:
                flt = Entity(name, type=RT.DATA_RUN.value, column=attr, selects=values)
                _all.append(flt)
                _filters.append(flt)
        self._all = tuple(_all)

    def __getitem__(self, idx):
        return self._all[idx]

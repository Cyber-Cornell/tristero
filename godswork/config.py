import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .store import identifier


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Target(Model):
    id: str
    worker: str
    host: str
    transport: Literal["ssh", "winrm"]
    credential: str
    port: int = Field(default=22, ge=1, le=65535)
    known_hosts: str | None = None
    ca_file: str | None = None

    @field_validator("id", "worker", "credential")
    @classmethod
    def ids(cls, value):
        return identifier(value)

    @field_validator("host")
    @classmethod
    def hostname(cls, value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", value):
                raise ValueError("Invalid hostname")
        return value

    @model_validator(mode="after")
    def trust(self):
        if self.transport == "ssh" and not self.known_hosts:
            raise ValueError("SSH requires a verified known_hosts file on the worker")
        if self.transport == "winrm" and not self.ca_file:
            raise ValueError("WinRM requires a CA file on the worker; use HTTPS port 5986")
        return self


class Service(Model):
    id: str
    target: str
    depends_on: list[str] = Field(default_factory=list)

    @field_validator("id", "target")
    @classmethod
    def ids(cls, value):
        return identifier(value)


class Inventory(Model):
    targets: list[Target]
    services: list[Service]


class TaskInput(Model):
    title: str = Field(min_length=1, max_length=200)
    instructions: str = Field(min_length=1, max_length=20000)
    resources: list[str] = Field(min_length=1, max_length=100)


class Credential(Model):
    target: str
    username: str = Field(min_length=1, max_length=200)
    rotate: bool = False
    rotation_kind: Literal["linux-local", "windows-local", "ad-user"] = "linux-local"
    account: str | None = None
    consumers: list[str] = Field(default_factory=list)
    consumer_usernames: dict[str, str] = Field(default_factory=dict)
    consumer_updates: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def scope(self):
        identifier(self.target)
        if self.rotate and not self.account:
            raise ValueError("Rotation requires the inventoried account name")
        if not set(self.consumer_updates).issubset(self.consumers) or not set(self.consumer_usernames).issubset(self.consumers):
            raise ValueError("Consumer settings must refer to declared consumers")
        if self.account and not re.fullmatch(r"[A-Za-z0-9_.@\\-]{1,200}", self.account):
            raise ValueError("Account name contains unsupported characters")
        if any(c in self.username for c in ("\n", "\r", "\x00")):
            raise ValueError("Invalid credential username")
        return self


class Observation(Model):
    id: str
    status: Literal["up", "down", "unknown"]


class Inject(Model):
    id: str
    title: str = Field(max_length=200)
    instructions: str = Field(max_length=20000)
    deadline: str = Field(max_length=100)

    @field_validator("id")
    @classmethod
    def ids(cls, value):
        return identifier(value)


class PortalSnapshot(Model):
    generated_at: float
    services: list[Observation]
    injects: list[Inject] = Field(default_factory=list)

# SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
#
# SPDX-License-Identifier: Apache-2.0

import os

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

API_KEY = os.getenv("API_KEY", "default-api-key-change-in-production")

api_key_header = APIKeyHeader(
    name="X-API-Key", description="API Key para autenticación"
)


async def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verifica que la API Key sea válida"""
    print(API_KEY)
    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="API Key inválida"
        )
    return api_key
